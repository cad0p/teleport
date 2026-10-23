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
	"strconv"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name:       "dismissed is a cancel, not a fallback",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitDismissed},
			wantErr:    errPresenceCancelled,
			wantPolkit: 1,
		},
		{
			name:       "unanswered dialog does not fall back",
			peer:       PresencePeer{UID: 1001, PIDFD: 7},
			fake:       fakePresence{polkitOutcome: polkitUnavailable, polkitErr: trace.Wrap(context.DeadlineExceeded)},
			wantErr:    context.DeadlineExceeded,
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

func TestClassifyPolkitResult(t *testing.T) {
	assert.Equal(t, polkitAuthorized, classifyPolkitResult(polkitAuthResult{IsAuthorized: true}))
	assert.Equal(t, polkitDismissed, classifyPolkitResult(polkitAuthResult{Details: map[string]string{"polkit.dismissed": "true"}}))
	assert.Equal(t, polkitUnavailable, classifyPolkitResult(polkitAuthResult{}))
	assert.Equal(t, polkitUnavailable, classifyPolkitResult(polkitAuthResult{IsChallenge: true}))
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

	_, err = srv.dispatch(alice, &helperRequest{Method: helperMethodAuthContextGuard, Params: params})
	require.NoError(t, err)
	assert.Equal(t, 1, f.polkitCalls)
	assert.Equal(t, alice, f.lastPeer)
}

func itoa(i int) string { return strconv.Itoa(i) }
