//go:build touchid

/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package touchid

// User presence through the desktop's polkit authentication agent.
//
// fprintd has no user interface of its own: a VerifyStart call just arms the
// sensor, so when tsh runs from a script or an agent nothing tells the user a
// tap is wanted. polkit's authentication agent does draw a dialog (on Omarchy,
// the quickshell agent, whose PAM stack accepts a fingerprint or the account
// password — the same "Touch ID or password" choice macOS LAContext offers).
//
// The helper therefore asks polkit first, for the connecting tsh process, and
// only falls back to the bare fprintd check when polkit cannot run an
// interactive check for that process (no agent, an inactive or remote session,
// polkit unreachable). An explicit cancel in the dialog, or an unanswered
// dialog, is a failure, not a fallback.

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/gravitational/trace"
)

const (
	// PolkitPresenceAction is the polkit action checked for user presence. Its
	// definition (allow_any=no, allow_inactive=no, allow_active=auth_self) ships
	// as tool/tsh-touchid-helper/com.github.cad0p.tsh-touchid.policy.
	PolkitPresenceAction = "com.github.cad0p.tsh-touchid.presence"

	polkitBusName        = "org.freedesktop.PolicyKit1"
	polkitAuthorityPath  = dbus.ObjectPath("/org/freedesktop/PolicyKit1/Authority")
	polkitAuthorityIface = "org.freedesktop.PolicyKit1.Authority"

	// polkitCheckAllowUserInteraction is CheckAuthorizationFlags.AllowUserInteraction.
	polkitCheckAllowUserInteraction = uint32(1)

	// polkitPromptTimeout bounds how long the dialog may stay unanswered.
	polkitPromptTimeout = 60 * time.Second
)

// PresencePeer identifies the process on the other end of a helper
// connection. UID comes from SO_PEERCRED. PIDFD is a pidfd for the peer
// (SO_PEERPIDFD), or -1 when none is available; without a pidfd the polkit
// path is skipped, because a bare pid can be recycled before polkit reads it.
type PresencePeer struct {
	UID   uint32
	PIDFD int
}

// polkitOutcome is the result of an interactive polkit check.
type polkitOutcome int

const (
	// polkitUnavailable: polkit could not run an interactive check for the
	// subject (no agent, inactive/remote session, D-Bus failure, not
	// authorized without a user decision). The caller falls back to fprintd.
	polkitUnavailable polkitOutcome = iota
	// polkitAuthorized: the user authenticated in the dialog.
	polkitAuthorized
	// polkitDismissed: the user cancelled the dialog.
	polkitDismissed
)

// errPresenceCancelled is returned when the user dismisses the polkit dialog.
var errPresenceCancelled = errors.New("user presence check cancelled in the authentication dialog")

// polkitCheck runs the interactive polkit check. It is a package variable so
// tests can substitute a fake.
var polkitCheck = polkitCheckDBus

// fingerprintCheck is the bare fprintd presence check, used as the fallback.
// It is a package variable so tests can substitute a fake.
var fingerprintCheck = verifyFingerprint

// verifyPolkitOrFingerprint is the default user-presence check: the polkit
// dialog when the peer can be identified and polkit can interact with the
// user, the fprintd check otherwise. It fails closed.
func verifyPolkitOrFingerprint(ctx context.Context, peer PresencePeer) error {
	if peer.PIDFD >= 0 {
		outcome, err := polkitCheck(ctx, peer)
		switch outcome {
		case polkitAuthorized:
			if err != nil {
				// Never trust an "authorized" that came with an error.
				return trace.Wrap(err)
			}
			return nil
		case polkitDismissed:
			if err != nil {
				return trace.Wrap(err)
			}
			return trace.Wrap(errPresenceCancelled)
		default:
			if err != nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
				// The dialog was shown and not answered: do not start a second,
				// invisible prompt.
				return trace.Wrap(err, "authentication dialog not answered")
			}
			logger.InfoContext(ctx, "polkit presence check unavailable, falling back to fprintd", "uid", peer.UID, "error", err)
		}
	}
	return trace.Wrap(fingerprintCheck(ctx, peer.UID))
}

// polkitSubject is the D-Bus (sa{sv}) polkit subject.
type polkitSubject struct {
	Kind    string
	Details map[string]dbus.Variant
}

// polkitAuthResult is the D-Bus (bba{ss}) polkit authorization result.
type polkitAuthResult struct {
	IsAuthorized bool
	IsChallenge  bool
	Details      map[string]string
}

var polkitCancellationSeq atomic.Uint64

// classifyPolkitResult maps a CheckAuthorization result to an outcome.
func classifyPolkitResult(res polkitAuthResult) polkitOutcome {
	switch {
	case res.IsAuthorized:
		return polkitAuthorized
	case res.Details["polkit.dismissed"] != "":
		return polkitDismissed
	default:
		return polkitUnavailable
	}
}

// polkitCheckDBus asks polkit, over the system bus, whether the peer process
// may perform PolkitPresenceAction, letting the authentication agent prompt.
func polkitCheckDBus(ctx context.Context, peer PresencePeer) (polkitOutcome, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return polkitUnavailable, trace.Wrap(err, "connecting to the system bus")
	}
	defer conn.Close()
	if !conn.SupportsUnixFDs() {
		return polkitUnavailable, trace.BadParameter("system bus connection does not support fd passing")
	}

	ctx, cancel := context.WithTimeout(ctx, polkitPromptTimeout)
	defer cancel()

	cancellationID := fmt.Sprintf("tsh-touchid-%d", polkitCancellationSeq.Add(1))
	subject := polkitSubject{
		Kind: "unix-process",
		Details: map[string]dbus.Variant{
			"pidfd": dbus.MakeVariant(dbus.UnixFD(int32(peer.PIDFD))),
			// polkit requires the uid alongside a pidfd, as an int32.
			"uid": dbus.MakeVariant(int32(peer.UID)),
		},
	}
	authority := conn.Object(polkitBusName, polkitAuthorityPath)

	// Probe without interaction first. The action is auth_self for active
	// sessions, so a correct setup answers "challenge". An immediate "yes"
	// means a local polkit rule grants the action outright, which would turn
	// the presence check into a no-op: refuse to treat that as presence and
	// let the caller fall back to the fingerprint.
	var probe polkitAuthResult
	if err := authority.CallWithContext(ctx, polkitAuthorityIface+".CheckAuthorization", 0,
		subject, PolkitPresenceAction, map[string]string{}, uint32(0), "",
	).Store(&probe); err != nil {
		return polkitUnavailable, trace.Wrap(err, "polkit CheckAuthorization (probe)")
	}
	switch {
	case probe.IsAuthorized:
		return polkitUnavailable, trace.AccessDenied("polkit grants %s without authentication; refusing it as a presence check", PolkitPresenceAction)
	case !probe.IsChallenge:
		// Not authorized and no challenge possible (allow_inactive/allow_any
		// are "no"): the peer is not in an active local session.
		return polkitUnavailable, trace.NotFound("polkit cannot prompt for this process (inactive or remote session)")
	}

	var res polkitAuthResult
	err = authority.CallWithContext(ctx, polkitAuthorityIface+".CheckAuthorization", 0,
		subject, PolkitPresenceAction, map[string]string{}, polkitCheckAllowUserInteraction, cancellationID,
	).Store(&res)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Close the dialog the agent may still be showing.
			_ = authority.Call(polkitAuthorityIface+".CancelCheckAuthorization", 0, cancellationID).Err
			return polkitUnavailable, trace.Wrap(ctxErr)
		}
		return polkitUnavailable, trace.Wrap(err, "polkit CheckAuthorization")
	}
	return classifyPolkitResult(res), nil
}
