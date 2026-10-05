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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
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

// TestReadKeyPayloadDecodesTrustedKeyHex pins the trusted-key wire format:
// KEYCTL_READ returns the sealed blob as an ASCII-hex string, and
// readKeyPayload must hand the raw blob on. Regressing to the hex form makes
// the S3 module hex-encode it again, so the SEP tries to unseal hex-of-hex and
// fails with EBADMSG.
func TestReadKeyPayloadDecodesTrustedKeyHex(t *testing.T) {
	raw := bytes.Repeat([]byte{0xa7}, 113)

	prev := keyctlReadPayload
	t.Cleanup(func() { keyctlReadPayload = prev })
	keyctlReadPayload = func(int) ([]byte, error) {
		return []byte(hex.EncodeToString(raw)), nil
	}

	got, err := readKeyPayload(0)
	require.NoError(t, err)
	assert.Equal(t, raw, got, "readKeyPayload must return the raw blob, not its hex form")
}

func TestDecodeSealedPayloadRejectsNonHex(t *testing.T) {
	for _, payload := range [][]byte{
		nil,
		[]byte("abc"),   // odd length
		[]byte("zz"),    // not hex
		[]byte("a5 b6"), // whitespace
	} {
		_, err := decodeSealedPayload(payload)
		require.Error(t, err, "payload %q", payload)
	}
}

// TestSaveKeyStoreFormat checks that the on-disk store holds the raw seal
// output and that loadKey feeds it back to unseal unchanged, so the blob
// format cannot silently become hex again.
func TestSaveKeyStoreFormat(t *testing.T) {
	dir := t.TempDir()
	SetStoreDir(dir)
	t.Cleanup(func() { SetStoreDir("") })

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	scalar, err := scalarBytesPadded(key.D)
	require.NoError(t, err)

	blob := bytes.Repeat([]byte{0x5a}, 113)

	prevSeal, prevUnseal := sealKeyMaterial, unsealKeyMaterial
	t.Cleanup(func() { sealKeyMaterial, unsealKeyMaterial = prevSeal, prevUnseal })
	sealKeyMaterial = func(in []byte) ([]byte, error) {
		assert.Equal(t, scalar, in)
		return blob, nil
	}
	unsealKeyMaterial = func(in []byte) ([]byte, error) {
		assert.Equal(t, blob, in, "unseal must receive the raw blob")
		return scalar, nil
	}

	require.NoError(t, saveKey("format-test", key))

	onDisk, err := os.ReadFile(filepath.Join(dir, "format-test.blob"))
	require.NoError(t, err)
	assert.Equal(t, blob, onDisk, "store must hold the raw sealed blob")

	// A fresh load must read the stored blob and unseal it directly.
	dropCachedKey("format-test")
	loaded, err := loadKey("format-test")
	require.NoError(t, err)
	assert.Equal(t, key.D, loaded.D)
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
