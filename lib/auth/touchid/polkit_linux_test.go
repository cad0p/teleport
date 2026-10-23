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

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fakePresence swaps the polkit and fprintd checks for fakes and records how
// often each ran.
type fakePresence struct {
	polkitOutcome polkitOutcome
	polkitErr     error
	fprintErr     error
	polkitCalls   int
	fprintCalls   int
	lastPeer      PresencePeer
}

func installFakePresence(t *testing.T, f *fakePresence) {
	t.Helper()
	prevP, prevF := polkitCheck, fingerprintCheck
	polkitCheck = func(_ context.Context, peer PresencePeer) (polkitOutcome, error) {
		f.polkitCalls++
		f.lastPeer = peer
		return f.polkitOutcome, f.polkitErr
	}
	fingerprintCheck = func(_ context.Context, _ uint32) error {
		f.fprintCalls++
		return f.fprintErr
	}
	t.Cleanup(func() { polkitCheck, fingerprintCheck = prevP, prevF })
}

func TestVerifyPolkitOrFingerprint(t *testing.T) {
	errFprint := errors.New("fprintd: no match")
	tests := []struct {
		name       string
		peer       PresencePeer
		fake       fakePresence
		wantErr    error // nil means success
		wantErrAny bool
		wantPolkit int
		wantFprint int
	}{
		{
			name:       "authorized in the dialog",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitAuthorized},
			wantPolkit: 1,
		},
		{
			name:       "authorized but with an error fails closed",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitAuthorized, polkitErr: errors.New("boom")},
			wantErrAny: true,
			wantPolkit: 1,
		},
		{
			name:       "dismissed with an error is still a cancel",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitDismissed, polkitErr: errors.New("x")},
			wantErr:    errPresenceCancelled,
			wantPolkit: 1,
		},
		{
			name:       "dismissed is a cancel, not a fallback",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitDismissed},
			wantErr:    errPresenceCancelled,
			wantPolkit: 1,
		},
		{
			name:       "unanswered dialog does not fall back",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitFailed, polkitErr: trace.Wrap(context.DeadlineExceeded)},
			wantErr:    context.DeadlineExceeded,
			wantPolkit: 1,
		},
		{
			name:       "failed attempts in the dialog do not fall back",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitFailed},
			wantErr:    errPresenceFailed,
			wantPolkit: 1,
		},
		{
			name:       "polkit unavailable falls back to fprintd (success)",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitUnavailable, polkitErr: trace.NotFound("inactive session")},
			wantPolkit: 1,
			wantFprint: 1,
		},
		{
			name:       "polkit auto-grant refused, fprintd decides (failure)",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitUnavailable, polkitErr: trace.AccessDenied("auto-grant"), fprintErr: errFprint},
			wantErr:    errFprint,
			wantPolkit: 1,
			wantFprint: 1,
		},
		{
			name:       "no pidfd skips polkit",
			peer:       PresencePeer{UID: 1001, PIDFD: -1},
			fake:       fakePresence{polkitOutcome: polkitAuthorized},
			wantFprint: 1,
		},
		{
			name:       "no pidfd and fprintd failure fails",
			peer:       PresencePeer{UID: 1001, PIDFD: -1},
			fake:       fakePresence{fprintErr: errFprint},
			wantErr:    errFprint,
			wantFprint: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fake
			installFakePresence(t, &f)
			err := verifyPolkitOrFingerprint(context.Background(), tt.peer)
			switch {
			case tt.wantErr != nil:
				require.ErrorIs(t, err, tt.wantErr)
			case tt.wantErrAny:
				require.Error(t, err)
			default:
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantPolkit, f.polkitCalls, "polkit calls")
			assert.Equal(t, tt.wantFprint, f.fprintCalls, "fprintd calls")
			if tt.wantPolkit > 0 {
				assert.Equal(t, tt.peer, f.lastPeer, "polkit must check the connection's peer")
			}
		})
	}
}

func TestClassifyInteractiveResult(t *testing.T) {
	assert.Equal(t, polkitAuthorized, classifyInteractiveResult(polkitAuthResult{IsAuthorized: true}))
	assert.Equal(t, polkitDismissed, classifyInteractiveResult(polkitAuthResult{Details: map[string]string{"polkit.dismissed": "true"}}))
	// Interactive "challenge" = no authentication agent: no dialog was shown.
	assert.Equal(t, polkitUnavailable, classifyInteractiveResult(polkitAuthResult{IsChallenge: true}))
	// Not authorized, not dismissed, no challenge = the user failed in the dialog.
	assert.Equal(t, polkitFailed, classifyInteractiveResult(polkitAuthResult{}))
}

// fakeAuthority records CheckAuthorization calls and answers from a script.
type fakeAuthority struct {
	probe       polkitAuthResult
	probeErr    error
	interactive polkitAuthResult
	interErr    error
	block       bool // the interactive call waits for ctx (an unanswered dialog)
	calls       []fakeAuthCall
	cancelled   []string
}

type fakeAuthCall struct {
	subject        polkitSubject
	details        map[string]string
	flags          uint32
	cancellationID string
}

func (f *fakeAuthority) checkAuthorization(ctx context.Context, subject polkitSubject, details map[string]string, flags uint32, cancellationID string) (polkitAuthResult, error) {
	f.calls = append(f.calls, fakeAuthCall{subject, details, flags, cancellationID})
	if flags == 0 {
		return f.probe, f.probeErr
	}
	if f.block {
		<-ctx.Done()
		return polkitAuthResult{}, ctx.Err()
	}
	return f.interactive, f.interErr
}

func (f *fakeAuthority) cancelCheckAuthorization(_ context.Context, id string) error {
	f.cancelled = append(f.cancelled, id)
	return nil
}

func TestPolkitCheckWith(t *testing.T) {
	peer := PresencePeer{UID: 1001, PIDFD: 9}
	challenge := polkitAuthResult{IsChallenge: true}

	t.Run("probe then interactive call with the peer as subject", func(t *testing.T) {
		f := &fakeAuthority{probe: challenge, interactive: polkitAuthResult{IsAuthorized: true}}
		out, err := polkitCheckWith(context.Background(), f, peer, "/usr/bin/tsh (pid 42)")
		require.NoError(t, err)
		assert.Equal(t, polkitAuthorized, out)
		require.Len(t, f.calls, 2)
		assert.Equal(t, uint32(0), f.calls[0].flags, "probe must not interact")
		assert.Equal(t, polkitCheckAllowUserInteraction, f.calls[1].flags, "second call must allow interaction")
		assert.NotEmpty(t, f.calls[1].cancellationID)
		for _, c := range f.calls {
			assert.Equal(t, "unix-process", c.subject.Kind)
			assert.Equal(t, dbus.UnixFD(9), c.subject.Details["pidfd"].Value())
			assert.Equal(t, int32(1001), c.subject.Details["uid"].Value())
		}
		assert.Contains(t, f.calls[1].details["polkit.message"], "/usr/bin/tsh (pid 42)")
	})

	t.Run("auto-granted action is refused without a dialog", func(t *testing.T) {
		f := &fakeAuthority{probe: polkitAuthResult{IsAuthorized: true}, interactive: polkitAuthResult{IsAuthorized: true}}
		out, err := polkitCheckWith(context.Background(), f, peer, "x")
		require.True(t, trace.IsAccessDenied(err), "err = %v", err)
		assert.Equal(t, polkitUnavailable, out)
		assert.Len(t, f.calls, 1)
	})

	t.Run("inactive session: no challenge, no dialog", func(t *testing.T) {
		f := &fakeAuthority{probe: polkitAuthResult{}}
		out, err := polkitCheckWith(context.Background(), f, peer, "x")
		require.True(t, trace.IsNotFound(err), "err = %v", err)
		assert.Equal(t, polkitUnavailable, out)
		assert.Len(t, f.calls, 1)
	})

	t.Run("probe error: no dialog", func(t *testing.T) {
		f := &fakeAuthority{probeErr: errors.New("bus down")}
		out, err := polkitCheckWith(context.Background(), f, peer, "x")
		require.Error(t, err)
		assert.Equal(t, polkitUnavailable, out)
		assert.Len(t, f.calls, 1)
	})

	t.Run("no agent: interactive challenge", func(t *testing.T) {
		f := &fakeAuthority{probe: challenge, interactive: challenge}
		out, err := polkitCheckWith(context.Background(), f, peer, "x")
		require.NoError(t, err)
		assert.Equal(t, polkitUnavailable, out)
	})

	t.Run("failed attempts", func(t *testing.T) {
		f := &fakeAuthority{probe: challenge, interactive: polkitAuthResult{}}
		out, err := polkitCheckWith(context.Background(), f, peer, "x")
		require.NoError(t, err)
		assert.Equal(t, polkitFailed, out)
	})

	t.Run("interactive call error fails closed", func(t *testing.T) {
		f := &fakeAuthority{probe: challenge, interErr: errors.New("disconnected")}
		out, err := polkitCheckWith(context.Background(), f, peer, "x")
		require.Error(t, err)
		assert.Equal(t, polkitFailed, out)
	})

	t.Run("unanswered dialog is cancelled and fails", func(t *testing.T) {
		f := &fakeAuthority{probe: challenge, block: true}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		out, err := polkitCheckWith(ctx, f, peer, "x")
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, polkitFailed, out)
		require.Len(t, f.cancelled, 1)
		assert.Equal(t, f.calls[1].cancellationID, f.cancelled[0], "the shown dialog must be cancelled")
	})
}

func TestSanitizeForDialog(t *testing.T) {
	assert.Equal(t, "/usr/bin/tsh", sanitizeForDialog("/usr/bin/tsh", 160))
	assert.Equal(t, "a?b", sanitizeForDialog("a\nb", 160))
	assert.Equal(t, "abc…", sanitizeForDialog("abcdef", 3))
}

func TestDescribeRequesterSelf(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd_open unavailable: %v", err)
	}
	defer unix.Close(fd)
	exe, err := os.Executable()
	require.NoError(t, err)
	got := describeRequester(fd)
	assert.Contains(t, got, "(pid "+strconv.Itoa(os.Getpid())+")")
	assert.Contains(t, got, filepath.Base(exe))
	assert.Equal(t, "an unidentified process", describeRequester(-1))
}

func TestPresenceFailureIsNotCached(t *testing.T) {
	f := fakePresence{polkitOutcome: polkitDismissed}
	installFakePresence(t, &f)
	svc := newSignService()
	peer := PresencePeer{UID: 1001, PIDFD: 7}

	require.ErrorIs(t, svc.ensureVerified(peer), errPresenceCancelled)
	require.ErrorIs(t, svc.ensureVerified(peer), errPresenceCancelled)
	assert.Equal(t, 2, f.polkitCalls, "a failed check must not open the reuse window")

	f.polkitOutcome = polkitAuthorized
	require.NoError(t, svc.ensureVerified(peer))
	require.NoError(t, svc.ensureVerified(peer))
	assert.Equal(t, 3, f.polkitCalls, "a success is reused within the window")

	// The window is per uid: another uid is asked again.
	require.NoError(t, svc.ensureVerified(PresencePeer{UID: 1002, PIDFD: 8}))
	assert.Equal(t, 4, f.polkitCalls)
}

func TestAuthContextBoundToCreatorUID(t *testing.T) {
	f := fakePresence{polkitOutcome: polkitAuthorized}
	installFakePresence(t, &f)
	srv := NewHelperServer()
	alice := PresencePeer{UID: 1001, PIDFD: 7}
	mallory := PresencePeer{UID: 1002, PIDFD: 8}

	res, err := srv.dispatch(alice, &helperRequest{Method: helperMethodNewAuthContext})
	require.NoError(t, err)
	ctxID := res.(newAuthContextResult).ContextID

	params := []byte(`{"context_id":` + itoa(ctxID) + `}`)
	_, err = srv.dispatch(mallory, &helperRequest{Method: helperMethodAuthContextGuard, Params: params})
	require.True(t, trace.IsAccessDenied(err), "guard from another uid: %v", err)
	_, err = srv.dispatch(mallory, &helperRequest{Method: helperMethodAuthenticate, Params: []byte(`{"context_id":` + itoa(ctxID) + `,"credential_id":"x","digest":""}`)})
	require.True(t, trace.IsAccessDenied(err), "authenticate from another uid: %v", err)
	assert.Equal(t, 0, f.polkitCalls, "a refused context must not prompt")

	_, err = srv.dispatch(mallory, &helperRequest{Method: helperMethodAuthContextClose, Params: params})
	require.True(t, trace.IsAccessDenied(err), "close from another uid: %v", err)

	_, err = srv.dispatch(alice, &helperRequest{Method: helperMethodAuthContextGuard, Params: params})
	require.NoError(t, err)
	assert.Equal(t, 1, f.polkitCalls)
	assert.Equal(t, alice, f.lastPeer)
}

func itoa(i int) string { return strconv.Itoa(i) }
