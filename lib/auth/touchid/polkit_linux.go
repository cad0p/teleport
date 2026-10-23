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
// The helper therefore asks polkit first, for the connecting process, and only
// falls back to the bare fprintd check when polkit cannot show a dialog for
// that process (no pidfd, no agent, an inactive or remote session, a local rule
// that grants the action without authentication, polkit unreachable before the
// dialog). Once a dialog has been shown, a cancel, failed attempts or no answer
// is a failure, not a fallback.
//
// The dialog says "Teleport Touch ID for <user>@<cluster> · <command>". The
// "<user>@<cluster>" part comes from the root-owned credential store entry the
// request would sign with, so the client cannot change it. The command is the
// requester's argv with argv[0] replaced by its real executable's basename: any
// process of an allowed uid can connect, and it controls its own argv, so the
// command says what the requester claims to be doing, not proof that it is
// tsh. The full executable path and command line are logged.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/gravitational/trace"
	"golang.org/x/sys/unix"
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
	// polkitProbeTimeout bounds the non-interactive calls (the probe and the
	// cancel).
	polkitProbeTimeout = 5 * time.Second
)

// PresencePeer identifies the process on the other end of a helper
// connection. UID comes from SO_PEERCRED. PIDFD is a pidfd for the peer
// (SO_PEERPIDFD), or -1 when none is available; without a pidfd the polkit
// path is skipped, because a bare pid can be recycled before polkit reads it.
//
// Reason says what the presence is for, for the dialog text. signService sets
// it from the root-owned credential store (e.g. "teleport-admin@teleport.pcad.it"),
// never from the client's request, so it is the trustworthy part of the text.
type PresencePeer struct {
	UID    uint32
	PIDFD  int
	Reason string
}

// polkitOutcome is the result of an interactive polkit check.
type polkitOutcome int

const (
	// polkitUnavailable: polkit could not show a dialog for the subject (no
	// pidfd, inactive or remote session, no authentication agent, an action
	// auto-granted by a local rule, polkit unreachable). No dialog was shown,
	// and the caller falls back to fprintd.
	polkitUnavailable polkitOutcome = iota
	// polkitAuthorized: the user authenticated in the dialog.
	polkitAuthorized
	// polkitDismissed: the user cancelled the dialog.
	polkitDismissed
	// polkitFailed: a dialog was shown and the user did not authenticate
	// (failed attempts). Like a cancel, this is final.
	polkitFailed
)

// errPresenceCancelled is returned when the user dismisses the polkit dialog.
var errPresenceCancelled = errors.New("user presence check cancelled in the authentication dialog")

// errPresenceFailed is returned when the user fails to authenticate in the
// polkit dialog.
var errPresenceFailed = errors.New("user presence check failed in the authentication dialog")

// polkitCheck runs the interactive polkit check. It is a package variable so
// tests can substitute a fake.
var polkitCheck = polkitCheckDBus

// fingerprintCheck is the bare fprintd presence check, used as the fallback.
// It is a package variable so tests can substitute a fake.
var fingerprintCheck = verifyFingerprint

// verifyPolkitOrFingerprint is the default user-presence check: the polkit
// dialog when the peer can be identified and polkit can show a dialog for it,
// the fprintd check otherwise. Once a dialog has been shown, its answer is
// final: a cancel, failed attempts or no answer within polkitPromptTimeout
// fail the check without starting a second, invisible fingerprint prompt.
// Every path either confirms presence or returns an error.
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
			return trace.Wrap(errPresenceCancelled)
		case polkitFailed:
			if err != nil {
				return trace.Wrap(err, "%s", errPresenceFailed)
			}
			return trace.Wrap(errPresenceFailed)
		default:
			logger.InfoContext(ctx, "polkit cannot show a presence dialog, falling back to fprintd", "uid", peer.UID, "error", err)
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

// polkitAuthority is the subset of org.freedesktop.PolicyKit1.Authority the
// presence check uses. It is an interface so the probe/prompt/cancel logic can
// be tested without a system bus.
type polkitAuthority interface {
	checkAuthorization(ctx context.Context, subject polkitSubject, details map[string]string, flags uint32, cancellationID string) (polkitAuthResult, error)
	cancelCheckAuthorization(ctx context.Context, cancellationID string) error
}

var polkitCancellationSeq atomic.Uint64

// classifyInteractiveResult maps the result of the interactive
// CheckAuthorization call to an outcome. polkit answers "challenge" to an
// interactive call only when it has no authentication agent for the subject's
// session (pkcheck reports that as "no agent is available"); that is the one
// interactive answer after which no dialog was shown.
func classifyInteractiveResult(res polkitAuthResult) polkitOutcome {
	switch {
	case res.IsAuthorized:
		return polkitAuthorized
	case res.Details["polkit.dismissed"] != "":
		return polkitDismissed
	case res.IsChallenge:
		return polkitUnavailable
	default:
		return polkitFailed
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
	return polkitCheckWith(ctx, dbusPolkitAuthority{obj: conn.Object(polkitBusName, polkitAuthorityPath)}, peer, describeRequester(peer.PIDFD))
}

// presenceMessage is the dialog text: what the presence is for (from the
// store), then the requesting command (from /proc; the caller controls its
// argv, so it comes second and is cut explicitly).
func presenceMessage(reason, requester string) string {
	if reason == "" {
		return "Teleport Touch ID · " + requester
	}
	return "Teleport Touch ID for " + sanitizeForDialog(reason, 80) + " · " + requester
}

// polkitCheckWith runs the probe and the interactive check against authority.
// requester describes the peer process for the dialog text.
func polkitCheckWith(ctx context.Context, authority polkitAuthority, peer PresencePeer, requester string) (polkitOutcome, error) {
	subject := polkitSubject{
		Kind: "unix-process",
		Details: map[string]dbus.Variant{
			"pidfd": dbus.MakeVariant(dbus.UnixFD(int32(peer.PIDFD))),
			// polkit requires the uid alongside a pidfd, as an int32.
			"uid": dbus.MakeVariant(int32(peer.UID)),
		},
	}

	// Probe without interaction first. The action is auth_self for active
	// sessions, so a correct setup answers "challenge". An immediate "yes"
	// means a local polkit rule grants the action outright, which would turn
	// the dialog into a no-op: refuse it as presence (the fingerprint check
	// then decides).
	probeCtx, cancelProbe := context.WithTimeout(ctx, polkitProbeTimeout)
	probe, err := authority.checkAuthorization(probeCtx, subject, map[string]string{}, 0, "")
	cancelProbe()
	if err != nil {
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

	// polkit.message is honoured for uid 0 callers (the helper runs as root),
	// so the dialog says which Teleport user/cluster and which command asks.
	// The Omarchy dialog shows it on one line and elides the middle when too
	// wide, so each part is bounded with an explicit cut marker.
	details := map[string]string{
		"polkit.message": presenceMessage(peer.Reason, requester),
	}
	ctx, cancel := context.WithTimeout(ctx, polkitPromptTimeout)
	defer cancel()
	cancellationID := fmt.Sprintf("tsh-touchid-%d", polkitCancellationSeq.Add(1))
	res, err := authority.checkAuthorization(ctx, subject, details, polkitCheckAllowUserInteraction, cancellationID)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// The dialog was shown and not answered. Close it, and fail: no
			// second, invisible prompt.
			cancelCtx, cancelCancel := context.WithTimeout(context.Background(), polkitProbeTimeout)
			_ = authority.cancelCheckAuthorization(cancelCtx, cancellationID)
			cancelCancel()
			return polkitFailed, trace.Wrap(ctxErr, "authentication dialog not answered")
		}
		// The call failed without an answer from the user; polkit may or may
		// not have shown a dialog. Fail rather than risk a second prompt.
		return polkitFailed, trace.Wrap(err, "polkit CheckAuthorization")
	}
	return classifyInteractiveResult(res), nil
}

// dbusPolkitAuthority implements polkitAuthority over D-Bus.
type dbusPolkitAuthority struct {
	obj dbus.BusObject
}

func (a dbusPolkitAuthority) checkAuthorization(ctx context.Context, subject polkitSubject, details map[string]string, flags uint32, cancellationID string) (polkitAuthResult, error) {
	var res polkitAuthResult
	err := a.obj.CallWithContext(ctx, polkitAuthorityIface+".CheckAuthorization", 0,
		subject, PolkitPresenceAction, details, flags, cancellationID,
	).Store(&res)
	return res, trace.Wrap(err)
}

func (a dbusPolkitAuthority) cancelCheckAuthorization(ctx context.Context, cancellationID string) error {
	return trace.Wrap(a.obj.CallWithContext(ctx, polkitAuthorityIface+".CancelCheckAuthorization", 0, cancellationID).Err)
}

// requesterCommandMax bounds the command shown in the dialog.
const requesterCommandMax = 60

// describeRequester names the process behind pidfd for the dialog: its
// command line, with argv[0] replaced by the basename of the real executable
// (/proc/<pid>/exe), read from /proc and confirmed against the pidfd
// afterwards so a recycled pid is never named. The arguments are the caller's
// own argv, so they say what the caller claims to be doing, not what it is;
// the full executable path and command line are logged. It never fails; an
// unknown process is described as such.
func describeRequester(pidfd int) string {
	const unknown = "an unidentified process"
	pid, err := pidFromPIDFD(pidfd)
	if err != nil || pid <= 0 {
		return unknown
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return unknown
	}
	rawArgs, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return unknown
	}
	// The pidfd still refers to a live process with this pid: the /proc reads
	// above were about the peer, not a successor.
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return unknown
	}
	args := strings.Split(strings.TrimRight(string(rawArgs), "\x00"), "\x00")
	words := append([]string{filepath.Base(exe)}, args[1:]...)
	cmd := strings.Join(words, " ")
	logger.InfoContext(context.Background(), "Presence requested", "pid", pid, "exe", exe, "cmdline", strings.Join(args, " "))
	return commandForDialog(cmd, requesterCommandMax)
}

// commandForDialog sanitizes cmd and, when it is longer than max, cuts it with
// an explicit marker saying how much was left out.
func commandForDialog(cmd string, max int) string {
	clean := sanitizeForDialog(cmd, len(cmd))
	if len(clean) <= max {
		return clean
	}
	return fmt.Sprintf("%s… (+%d chars)", clean[:max], len(clean)-max)
}

// pidFromPIDFD reads the pid a pidfd refers to from /proc/self/fdinfo.
func pidFromPIDFD(pidfd int) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil {
		return 0, trace.Wrap(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(v))
			return pid, trace.Wrap(err)
		}
	}
	return 0, trace.NotFound("no Pid in fdinfo")
}

// sanitizeForDialog keeps printable ASCII and bounds the length, marking a
// cut explicitly.
func sanitizeForDialog(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}
	out := b.String()
	if len(out) > max {
		out = out[:max] + "…"
	}
	return out
}
