//go:build touchid

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

// SEP-sealed key material (I1b).
//
// The P-256 private scalar is sealed at rest with the SEP-backed "trusted" key
// source and stored as a root-only blob; the plaintext only exists in the
// daemon's memory after it unseals the blob through /dev/trusted_unseal (the S3
// userspace-unseal core). Sealing is a host-side ECIES encryption to the cached
// machine ref-key, so it works without the device, but a successful seal does
// not prove the blob can be unsealed (keybag/ref-key state matters); every seal
// is therefore verified by an immediate unseal before it is trusted.
//
// Security model (S3): /dev/trusted_unseal is a root-only bearer oracle with no
// presence gate. The blob is not a secret in the cryptographic sense, but it is
// kept 0600 root because possession plus the device equals the unsealed key.
// The fingerprint check lives in the daemon and is UX, not part of this
// primitive.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"sync/atomic"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/sys/unix"
)

const (
	// trustedUnsealDevice is the root-only misc device added by the S3 core.
	trustedUnsealDevice = "/dev/trusted_unseal"
	// scalarLen is the P-256 scalar length in bytes.
	scalarLen = 32
	// trustedSourceName is the trust source registered by the SEP driver.
	trustedSourceName = "trusted"
	// maxBlobSize bounds the unseal input we are willing to write.
	maxBlobSize = 4096
)

// sealKeyMaterial seals a 32-byte P-256 scalar. It is a package variable so
// tests can substitute a fake implementation on machines without the SEP.
var sealKeyMaterial = sealScalarWithSEP

// unsealKeyMaterial unseals a blob produced by sealKeyMaterial. It is a package
// variable so tests can substitute a fake implementation.
var unsealKeyMaterial = unsealBlobWithDevice

// sealCounter makes the key descriptions unique within a process, so sealing
// never hits the (non-migratable) trusted_update path.
var sealCounter atomic.Uint64

// sealScalarWithSEP seals scalar through the SEP-backed "trusted" key source
// and returns the sealed blob.
func sealScalarWithSEP(scalar []byte) ([]byte, error) {
	if len(scalar) != scalarLen {
		return nil, trace.BadParameter("expected a %d-byte scalar, got %d", scalarLen, len(scalar))
	}

	desc := fmt.Sprintf("tsh-touchid-seal-%d-%d-%d", os.Getpid(), time.Now().UnixNano(), sealCounter.Add(1))
	payload := []byte("import " + hex.EncodeToString(scalar))

	// Prefer the session keyring, but a systemd service may not have one; the
	// process keyring is always present.
	keyID, err := unix.AddKey(trustedSourceName, desc, payload, unix.KEY_SPEC_SESSION_KEYRING)
	ringID := unix.KEY_SPEC_SESSION_KEYRING
	if err != nil {
		keyID, err = unix.AddKey(trustedSourceName, desc+"-p", payload, unix.KEY_SPEC_PROCESS_KEYRING)
		ringID = unix.KEY_SPEC_PROCESS_KEYRING
		if err != nil {
			return nil, trace.Wrap(err, "seal key material")
		}
	}
	defer func() {
		if _, uerr := unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, ringID, 0, 0); uerr != nil {
			logger.Debug("Failed to unlink sealing key", "error", uerr)
		}
	}()

	return readKeyPayload(keyID)
}

// maxHexPayloadSize bounds the trusted-key payload as returned by KEYCTL_READ:
// two ASCII hex characters per sealed blob byte.
const maxHexPayloadSize = 2 * maxBlobSize

// keyctlReadPayload reads the bytes KEYCTL_READ returns for a key. It is a
// package variable so tests can substitute a fake kernel response.
var keyctlReadPayload = func(keyID int) ([]byte, error) {
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, nil, 0)
	if err != nil {
		return nil, trace.Wrap(err, "read sealed key length")
	}
	if n <= 0 || n > maxHexPayloadSize {
		return nil, trace.Errorf("unexpected sealed key size %d", n)
	}
	buf := make([]byte, n)
	read, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buf, 0)
	if err != nil {
		return nil, trace.Wrap(err, "read sealed key")
	}
	if read <= 0 || read > n {
		return nil, trace.BadParameter("empty sealed key payload")
	}
	return buf[:read], nil
}

// readKeyPayload returns the sealed blob for a trusted key. KEYCTL_READ
// exposes a trusted key's payload as an ASCII-hex string (two characters per
// blob byte), not as the raw blob, so decode it before it reaches
// unsealBlobWithDevice: writing the hex form to the device would have the
// module hex-encode it again and unseal hex-of-hex, which the SEP rejects with
// EBADMSG.
func readKeyPayload(keyID int) ([]byte, error) {
	payload, err := keyctlReadPayload(keyID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return decodeSealedPayload(payload)
}

// decodeSealedPayload decodes a trusted key's ASCII-hex payload into the raw
// sealed blob.
func decodeSealedPayload(payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload)%2 != 0 {
		return nil, trace.BadParameter("trusted key payload is not hex (length %d)", len(payload))
	}
	blob := make([]byte, hex.DecodedLen(len(payload)))
	if _, err := hex.Decode(blob, payload); err != nil {
		return nil, trace.Wrap(err, "decode trusted key payload")
	}
	if len(blob) > maxBlobSize {
		return nil, trace.Errorf("unexpected sealed key size %d", len(blob))
	}
	return blob, nil
}

// unsealBlobWithDevice recovers the plaintext scalar from blob through the S3
// userspace-unseal device. Write and read share one open fd.
func unsealBlobWithDevice(blob []byte) ([]byte, error) {
	if len(blob) == 0 || len(blob) > maxBlobSize {
		return nil, trace.BadParameter("invalid sealed blob size %d", len(blob))
	}

	fd, err := unix.Open(trustedUnsealDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, trace.Wrap(err, "open %s", trustedUnsealDevice)
	}
	defer unix.Close(fd)

	if _, err := unix.Write(fd, blob); err != nil {
		return nil, trace.Wrap(err, "write sealed blob")
	}

	out := make([]byte, 0, scalarLen)
	buf := make([]byte, 64)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, trace.Wrap(err, "read unsealed key")
		}
		if n == 0 {
			break
		}
		out = append(out, buf[:n]...)
		if len(out) > maxBlobSize {
			return nil, trace.BadParameter("unsealed key larger than expected")
		}
	}
	if len(out) != scalarLen {
		return nil, trace.Errorf("unsealed key has %d bytes, want %d", len(out), scalarLen)
	}
	return out, nil
}

// verifySealRoundTrip seals scalar and immediately unseals it, comparing the
// result. A successful seal is not proof of unsealability, so callers must gate
// on this before treating a blob as usable.
func verifySealRoundTrip(scalar []byte) ([]byte, error) {
	blob, err := sealKeyMaterial(scalar)
	if err != nil {
		return nil, trace.Wrap(err, "seal")
	}
	got, err := unsealKeyMaterial(blob)
	if err != nil {
		return nil, trace.Wrap(err, "seal self-check (unseal)")
	}
	if !bytes.Equal(got, scalar) {
		return nil, trace.BadParameter("sealed key round-trip mismatch")
	}
	return blob, nil
}

// scalarBytesPadded returns the big-endian scalar, left-padded to 32 bytes.
func scalarBytesPadded(d *big.Int) ([]byte, error) {
	b := d.Bytes()
	if len(b) > scalarLen {
		return nil, trace.BadParameter("scalar larger than %d bytes", scalarLen)
	}
	out := make([]byte, scalarLen)
	copy(out[scalarLen-len(b):], b)
	return out, nil
}

// ecdsaFromScalar rebuilds a P-256 private key from a 32-byte big-endian
// scalar. The public point is derived, so no other material is needed at rest.
func ecdsaFromScalar(scalar []byte) (*ecdsa.PrivateKey, error) {
	if len(scalar) != scalarLen {
		return nil, trace.BadParameter("expected a %d-byte scalar, got %d", scalarLen, len(scalar))
	}
	n := elliptic.P256().Params().N
	d := new(big.Int).SetBytes(scalar)
	if d.Sign() == 0 || d.Cmp(n) >= 0 {
		return nil, trace.BadParameter("scalar out of range")
	}
	x, y := elliptic.P256().ScalarBaseMult(scalar)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}, nil
}
