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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECDSAScalarRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	scalar, err := scalarBytesPadded(key.D)
	require.NoError(t, err)
	require.Len(t, scalar, scalarLen)

	rebuilt, err := ecdsaFromScalar(scalar)
	require.NoError(t, err)
	assert.Equal(t, key.D, rebuilt.D)
	assert.Equal(t, key.PublicKey.X, rebuilt.PublicKey.X)
	assert.Equal(t, key.PublicKey.Y, rebuilt.PublicKey.Y)

	_, err = ecdsaFromScalar(make([]byte, scalarLen))
	require.Error(t, err, "zero scalar must be rejected")
}

// TestSEPSealedStoreRoundTrip exercises the real seal -> unseal loop through the
// SEP-backed trusted source and /dev/trusted_unseal. It is skipped when the S3
// unseal module is not loaded.
func TestSEPSealedStoreRoundTrip(t *testing.T) {
	if _, err := os.Stat(trustedUnsealDevice); err != nil {
		t.Skipf("%s not present, skipping hardware seal test", trustedUnsealDevice)
	}

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	SetStoreDir(t.TempDir())
	t.Cleanup(func() { SetStoreDir("") })

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	require.NoError(t, saveKey("seal-test", key))

	// A fresh load must come from the sealed blob, not the in-memory cache.
	dropCachedKey("seal-test")
	loaded, err := loadKey("seal-test")
	require.NoError(t, err)
	assert.Equal(t, key.D, loaded.D)

	require.NoError(t, deleteKey("seal-test"))
}
