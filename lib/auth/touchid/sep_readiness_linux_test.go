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
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubReadSEPDiag installs a fake diag reader for the duration of the test.
func stubReadSEPDiag(t *testing.T, fn func() (sepDiag, bool)) {
	t.Helper()
	prev := readSEPDiag
	readSEPDiag = fn
	t.Cleanup(func() { readSEPDiag = prev })
}

// stubPreloadAllKeys installs a fake unseal for the duration of the test.
func stubPreloadAllKeys(t *testing.T, fn func() error) {
	t.Helper()
	prev := preloadAllKeys
	preloadAllKeys = fn
	t.Cleanup(func() { preloadAllKeys = prev })
}

// speedUpBackoff keeps the bounded-wait tests quick.
func speedUpBackoff(t *testing.T) {
	t.Helper()
	prevPoll, prevBase, prevMax := sepReadyPollInterval, sepUnsealBaseBackoff, sepUnsealMaxBackoff
	sepReadyPollInterval, sepUnsealBaseBackoff, sepUnsealMaxBackoff = time.Millisecond, time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() {
		sepReadyPollInterval, sepUnsealBaseBackoff, sepUnsealMaxBackoff = prevPoll, prevBase, prevMax
	})
}

func TestSEPDiagReady(t *testing.T) {
	assert.True(t, sepDiag{Keystore: "open"}.ready())
	assert.False(t, sepDiag{Keystore: "unknown"}.ready())
	assert.False(t, sepDiag{Keystore: "closed"}.ready())
	assert.False(t, sepDiag{}.ready())
}

func TestUnsealBackoffIsCapped(t *testing.T) {
	prevBase, prevMax := sepUnsealBaseBackoff, sepUnsealMaxBackoff
	sepUnsealBaseBackoff, sepUnsealMaxBackoff = 100*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { sepUnsealBaseBackoff, sepUnsealMaxBackoff = prevBase, prevMax })

	assert.Equal(t, 100*time.Millisecond, unsealBackoff(1))
	assert.Equal(t, 200*time.Millisecond, unsealBackoff(2))
	assert.Equal(t, 400*time.Millisecond, unsealBackoff(3))
	assert.Equal(t, 400*time.Millisecond, unsealBackoff(10), "backoff must stay capped")
}

func TestHasSealedCredentials(t *testing.T) {
	dir := t.TempDir()
	SetStoreDir(dir)
	t.Cleanup(func() { SetStoreDir("") })

	ok, err := hasSealedCredentials()
	require.NoError(t, err)
	assert.False(t, ok, "an empty store has nothing to unseal")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "abc.blob"), []byte("x"), 0600))
	ok, err = hasSealedCredentials()
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestUnsealWithBackoffNoCredentials pins that an empty store does not wait for
// the SEP at all and never touches the unseal device.
func TestUnsealWithBackoffNoCredentials(t *testing.T) {
	SetStoreDir(t.TempDir())
	t.Cleanup(func() { SetStoreDir("") })

	var calls atomic.Int32
	stubPreloadAllKeys(t, func() error {
		calls.Add(1)
		return errors.New("must not be called")
	})

	require.NoError(t, UnsealWithBackoff(50*time.Millisecond))
	assert.Zero(t, calls.Load(), "no credentials means no unseal attempt")
}

// TestUnsealWithBackoffWaitsForKeystore pins the preferred readiness path: the
// first diag read sees the key store still coming up, the wait loop then sees
// it open, and only then does the unseal run.
func TestUnsealWithBackoffWaitsForKeystore(t *testing.T) {
	speedUpBackoff(t)
	SetStoreDir(t.TempDir())
	t.Cleanup(func() { SetStoreDir("") })
	require.NoError(t, os.WriteFile(filepath.Join(mustCredsDir(t), "c.blob"), []byte("x"), 0600))

	var diagCalls atomic.Int32
	stubReadSEPDiag(t, func() (sepDiag, bool) {
		if diagCalls.Add(1) == 1 {
			return sepDiag{ABI: "1", Keystore: "unknown", Keybag: "unknown", Attach: "attached"}, true
		}
		return sepDiag{ABI: "1", Keystore: "open", Keybag: "present", Attach: "attached"}, true
	})

	var unsealCalls atomic.Int32
	stubPreloadAllKeys(t, func() error {
		unsealCalls.Add(1)
		return nil
	})

	require.NoError(t, UnsealWithBackoff(2*time.Second))
	assert.GreaterOrEqual(t, diagCalls.Load(), int32(2), "must have polled the key store before unsealing")
	assert.EqualValues(t, 1, unsealCalls.Load())
}

// TestUnsealWithBackoffFailsClosed pins that once the key store is open a
// persistent unseal failure is retried with backoff and then surfaces as an
// error, so the daemon exits non-zero instead of serving without keys.
func TestUnsealWithBackoffFailsClosed(t *testing.T) {
	speedUpBackoff(t)
	SetStoreDir(t.TempDir())
	t.Cleanup(func() { SetStoreDir("") })
	require.NoError(t, os.WriteFile(filepath.Join(mustCredsDir(t), "c.blob"), []byte("x"), 0600))

	stubReadSEPDiag(t, func() (sepDiag, bool) {
		return sepDiag{ABI: "1", Keystore: "open", Keybag: "present", Attach: "attached"}, true
	})

	var calls atomic.Int32
	sentinel := errors.New("bad message")
	stubPreloadAllKeys(t, func() error {
		calls.Add(1)
		return sentinel
	})

	err := UnsealWithBackoff(150 * time.Millisecond)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	assert.Greater(t, calls.Load(), int32(1), "a transient failure must be retried")
}

func mustCredsDir(t *testing.T) string {
	t.Helper()
	dir, err := credsDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0700))
	return dir
}
