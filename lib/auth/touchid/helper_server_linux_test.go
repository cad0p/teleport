//go:build linux && touchid

/*
 * Teleport
 * Copyright (C) 2026  Gravitational, Inc.
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTestHelper wires a helperNative client to a real HelperServer over a
// unix socket in a temp dir, with fprintd presence and SEP sealing replaced by
// in-memory fakes. It returns the client and the number of fake presence checks
// so far.
func startTestHelper(t *testing.T) (*helperNative, *int32) {
	t.Helper()

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	path := filepath.Join(t.TempDir(), helperSocketName)
	t.Setenv("TSH_TOUCHID_SOCKET", path)

	l, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	srv := NewHelperServer()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = srv.ServeConn(c, uint32(os.Getuid())) }()
		}
	}()

	var calls int32
	prev := verifyPresence
	verifyPresence = func(context.Context, PresencePeer) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	t.Cleanup(func() { verifyPresence = prev })

	// Fake the SEP seal/unseal: identity keeps the round-trip self-check honest
	// without the unseal device.
	prevSeal, prevUnseal := sealKeyMaterial, unsealKeyMaterial
	sealKeyMaterial = func(scalar []byte) ([]byte, error) { return append([]byte(nil), scalar...), nil }
	unsealKeyMaterial = func(blob []byte) ([]byte, error) { return append([]byte(nil), blob...), nil }
	t.Cleanup(func() { sealKeyMaterial, unsealKeyMaterial = prevSeal, prevUnseal })

	return &helperNative{}, &calls
}

func TestHelperRegisterFindDelete(t *testing.T) {
	h, calls := startTestHelper(t)

	info, err := h.Register("example.com", "alice", []byte("handle"))
	require.NoError(t, err)
	require.NotEmpty(t, info.CredentialID)
	require.NotEmpty(t, info.publicKeyRaw)
	// Registration requires presence (one dialog naming the new label).
	require.Equal(t, int32(1), atomic.LoadInt32(calls))

	// FindCredentials does not require presence.
	creds, err := h.FindCredentials("example.com", "alice")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, info.CredentialID, creds[0].CredentialID)
	assert.Equal(t, "alice", creds[0].User.Name)
	assert.Equal(t, []byte("handle"), creds[0].User.UserHandle)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))

	require.NoError(t, h.DeleteNonInteractive(info.CredentialID))
	creds, err = h.FindCredentials("example.com", "alice")
	require.NoError(t, err)
	require.Empty(t, creds)
}

// TestPasswordlessDiscovery pins the prerequisite of passwordless login on
// Linux. tsh decides whether to skip the password prompt via
// client.canDefaultToPasswordless -> touchid.HasCredentials ->
// native.FindCredentials(rpID, "") -- an username-less lookup, as the case
// must be discoverable from the rpID alone. This mirrors macOS, where the
// same call enumerates the Secure Enclave keychain.
func TestPasswordlessDiscovery(t *testing.T) {
	h, calls := startTestHelper(t)

	tidAlice, err := h.Register("teleport.example.com", "alice", []byte("alice-handle"))
	require.NoError(t, err)
	tidBob, err := h.Register("teleport.example.com", "bob", []byte("bob-handle"))
	require.NoError(t, err)
	// A credential for another rpID must never be returned.
	_, err = h.Register("other.example.com", "carol", []byte("carol-handle"))
	require.NoError(t, err)
	afterRegister := atomic.LoadInt32(calls)

	// Username-less discovery (the passwordless call) returns every credential
	// for the rpID, with the user handle that resolves the Teleport user.
	creds, err := h.FindCredentials("teleport.example.com", "")
	require.NoError(t, err)
	require.Len(t, creds, 2)
	got := map[string]string{}
	for _, c := range creds {
		got[c.User.Name] = string(c.User.UserHandle)
	}
	assert.Equal(t, map[string]string{
		"alice": "alice-handle",
		"bob":   "bob-handle",
	}, got)
	assert.Equal(t, afterRegister, atomic.LoadInt32(calls), "discovery must not require presence")

	// An explicit user narrows to that user's credential.
	creds, err = h.FindCredentials("teleport.example.com", "bob")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, tidBob.CredentialID, creds[0].CredentialID)

	// Sanity check the other credential is a distinct, discoverable device.
	assert.NotEqual(t, tidAlice.CredentialID, tidBob.CredentialID)
}

func TestHelperAuthenticateSignsAndReusesPresence(t *testing.T) {
	h, calls := startTestHelper(t)

	info, err := h.Register("example.com", "alice", []byte("handle"))
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("hello"))
	sig, err := h.Authenticate(nil, info.CredentialID, digest[:])
	require.NoError(t, err)

	x, y := elliptic.Unmarshal(elliptic.P256(), info.publicKeyRaw)
	require.NotNil(t, x)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig), "signature must verify")

	// One prompt for the registration, one for the first signature with the
	// credential...
	require.Equal(t, int32(2), atomic.LoadInt32(calls))
	// ...and the 10s reuse window suppresses the second prompt for the same
	// credential.
	_, err = h.Authenticate(nil, info.CredentialID, digest[:])
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(calls))

	// An approval for one credential never covers another (round-4 red-team F2).
	other, err := h.Register("example.com", "bob", []byte("bob"))
	require.NoError(t, err)
	before := atomic.LoadInt32(calls)
	_, err = h.Authenticate(nil, other.CredentialID, digest[:])
	require.NoError(t, err)
	assert.Equal(t, before+1, atomic.LoadInt32(calls), "a different credential must prompt again")
}

// TestPresenceReasonFromStore pins that the dialog's "for <user>@<rp id>" comes
// from the root-owned store entry of the credential being used, and that an
// unknown credential is refused before any prompt.
func TestPresenceReasonFromStore(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	prevSeal, prevUnseal := sealKeyMaterial, unsealKeyMaterial
	sealKeyMaterial = func(scalar []byte) ([]byte, error) { return append([]byte(nil), scalar...), nil }
	unsealKeyMaterial = func(blob []byte) ([]byte, error) { return append([]byte(nil), blob...), nil }
	t.Cleanup(func() { sealKeyMaterial, unsealKeyMaterial = prevSeal, prevUnseal })

	var reasons []string
	prev := verifyPresence
	verifyPresence = func(_ context.Context, p PresencePeer) error {
		reasons = append(reasons, p.Reason)
		return nil
	}
	t.Cleanup(func() { verifyPresence = prev })

	info, err := registerCredential("teleport.pcad.it", "teleport-admin", []byte("h"))
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("x"))

	svc := newSignService()
	_, err = svc.authenticate(PresencePeer{UID: 1001, PIDFD: -1}, "no-such-credential", digest[:])
	require.True(t, trace.IsNotFound(err), "unknown credential: %v", err)
	assert.Empty(t, reasons, "an unknown credential must not prompt")

	_, err = svc.authenticate(PresencePeer{UID: 1001, PIDFD: -1}, info.CredentialID, digest[:])
	require.NoError(t, err)
	require.NoError(t, svc.deleteCredential(PresencePeer{UID: 1002, PIDFD: -1}, info.CredentialID))
	_, err = svc.listCredentials(PresencePeer{UID: 1003, PIDFD: -1})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"teleport-admin@teleport.pcad.it",
		"deleting teleport-admin@teleport.pcad.it",
		"listing Touch ID credentials",
	}, reasons)

	// Registration goes through a dialog naming the label it creates.
	reasons = nil
	_, err = svc.register(PresencePeer{UID: 1001, PIDFD: -1}, "teleport.pcad.it", "pier", []byte("p"))
	require.NoError(t, err)
	assert.Equal(t, []string{"registering pier@teleport.pcad.it"}, reasons)
}

func TestHelperAuthContext(t *testing.T) {
	h, calls := startTestHelper(t)

	info, err := h.Register("example.com", "alice", []byte("handle"))
	require.NoError(t, err)

	actx := h.NewAuthContext()
	require.NotNil(t, actx)

	var ran bool
	require.NoError(t, actx.Guard(func() { ran = true }))
	assert.True(t, ran)
	require.Equal(t, int32(2), atomic.LoadInt32(calls)) // register + guard

	// A Guard approval ("choosing a Teleport user") does not cover signing
	// with a specific credential: that dialog names the credential.
	digest := sha256.Sum256([]byte("hello"))
	_, err = h.Authenticate(actx, info.CredentialID, digest[:])
	require.NoError(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(calls))
	actx.Close()
}

func TestHelperDiag(t *testing.T) {
	h, _ := startTestHelper(t)

	diag, err := h.Diag()
	require.NoError(t, err)
	assert.True(t, diag.HasCompileSupport)
}

func TestHelperUnknownMethod(t *testing.T) {
	h, _ := startTestHelper(t)

	require.Error(t, h.sendRequest("Bogus", nil, nil))
}
