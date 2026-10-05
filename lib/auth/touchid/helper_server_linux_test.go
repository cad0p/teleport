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
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTestHelper wires a helperNative client to a real HelperServer over a
// unix socket in a temp dir, with fprintd presence replaced by a counting fake.
// It returns the client and the number of fake presence checks so far.
func startTestHelper(t *testing.T) (*helperNative, *int32) {
	t.Helper()

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	path, err := helperSocketPath()
	require.NoError(t, err)

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
	verifyPresence = func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	t.Cleanup(func() { verifyPresence = prev })

	return &helperNative{}, &calls
}

func TestHelperRegisterFindDelete(t *testing.T) {
	h, calls := startTestHelper(t)

	info, err := h.Register("example.com", "alice", []byte("handle"))
	require.NoError(t, err)
	require.NotEmpty(t, info.CredentialID)
	require.NotEmpty(t, info.publicKeyRaw)

	// FindCredentials does not require presence.
	creds, err := h.FindCredentials("example.com", "alice")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, info.CredentialID, creds[0].CredentialID)
	assert.Equal(t, "alice", creds[0].User.Name)
	assert.Equal(t, []byte("handle"), creds[0].User.UserHandle)
	assert.Equal(t, int32(0), atomic.LoadInt32(calls))

	require.NoError(t, h.DeleteNonInteractive(info.CredentialID))
	creds, err = h.FindCredentials("example.com", "alice")
	require.NoError(t, err)
	require.Empty(t, creds)
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

	// The daemon prompted exactly once...
	require.Equal(t, int32(1), atomic.LoadInt32(calls))
	// ...and the 10s reuse window suppresses the second prompt.
	_, err = h.Authenticate(nil, info.CredentialID, digest[:])
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
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
	require.Equal(t, int32(1), atomic.LoadInt32(calls))

	// Authenticate through the context reuses the Guard verification.
	digest := sha256.Sum256([]byte("hello"))
	_, err = h.Authenticate(actx, info.CredentialID, digest[:])
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
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
