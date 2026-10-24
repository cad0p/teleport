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

// Linux implementation of the Touch ID helper daemon, enabled with the
// "touchid" build tag.
//
// This file holds the daemon-side "core": the credential store and the fprintd
// presence check. It is intentionally separate from the tsh-side client
// (api_linux_helper.go), which talks to this core over an AF_UNIX socket.
//
// It stands in for the macOS Touch ID/Secure Enclave primitives with:
//
//   - a software P-256 key, sealed at rest with the SEP-backed "trusted" key
//     source as a root-only blob under /var/lib/tsh-touchid (0600) and unsealed
//     into the daemon's memory at start-up (see sealed_store_linux.go); and
//   - user presence via the desktop's polkit authentication dialog (fingerprint
//     or password, see polkit_linux.go), with an fprintd fingerprint
//     verification over D-Bus (net.reactivated.Fprint) as the fallback when no
//     dialog can be shown.
//
// Note that, unlike macOS, the presence check is still not a key-access
// control: once the daemon has unsealed a key it lives in the daemon's memory,
// and /dev/trusted_unseal is a root-only bearer oracle (S3), so the prompt
// remains a presence check, not a cryptographic boundary. What I1b adds
// is that the plaintext is never stored in a user-readable file, the unseal
// happens only inside the root daemon, and the key never reaches the tsh
// process: tsh only sends a digest and receives a signature.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	"github.com/gravitational/trace"
)

const (
	// credsDirName is the directory, relative to the user's config directory,
	// where Linux touchid credentials are stored.
	credsDirName = "tsh-touchid"
	// credsFileName is the credentials metadata file.
	credsFileName = "credentials.json"

	// keyPEMType is the PEM block type used for private keys.
	keyPEMType = "PRIVATE KEY"

	// fingerprintReuseWindow is how long a successful fingerprint verification
	// is reused, mirroring the ~10s reuse window of macOS LAContext.
	fingerprintReuseWindow = 10 * time.Second
	// fingerprintVerifyTimeout is how long we wait for a fingerprint before
	// giving up on a single verification attempt.
	fingerprintVerifyTimeout = 60 * time.Second
	// fingerprintVerifyAttempts is how many times a verification is started
	// before giving up. The aurora-linux apple_sep driver can fail a capture
	// with a transient device error right after the sensor is (re)registered
	// (aurora-linux #25); the next VerifyStart usually arms the sensor again.
	fingerprintVerifyAttempts = 4

	// fprintd D-Bus coordinates.
	fprintdBusName      = "net.reactivated.Fprint"
	fprintdManagerPath  = dbus.ObjectPath("/net/reactivated/Fprint/Manager")
	fprintdManagerIface = "net.reactivated.Fprint.Manager"
	fprintdDeviceIface  = "net.reactivated.Fprint.Device"
)

// storedCredential is the metadata persisted for each Linux touchid credential.
type storedCredential struct {
	CredentialID string    `json:"credential_id"`
	RPID         string    `json:"rp_id"`
	UserName     string    `json:"user_name"`
	UserHandle   string    `json:"user_handle"` // base64.RawURLEncoding
	CreateTime   time.Time `json:"create_time"`
}

// credsMu serializes read-modify-write cycles on the credentials metadata
// within the daemon process.
var credsMu sync.Mutex

// storeDirOverride, when set, replaces the default per-user credential store
// directory. The privileged daemon points it at the system state directory so
// the key material is not under the user's home.
var storeDirOverride string

// SetStoreDir overrides the credential store directory used by the daemon.
func SetStoreDir(dir string) {
	storeDirOverride = dir
}

func credsDir() (string, error) {
	if storeDirOverride != "" {
		return storeDirOverride, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", trace.Wrap(err)
	}
	return filepath.Join(base, credsDirName), nil
}

// ensureCredsDir creates the credentials directory (0700) if needed.
func ensureCredsDir() (string, error) {
	dir, err := credsDir()
	if err != nil {
		return "", trace.Wrap(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", trace.Wrap(err)
	}
	// Defend against a pre-existing directory with lax permissions and a
	// restrictive umask on create.
	if err := os.Chmod(dir, 0700); err != nil {
		return "", trace.Wrap(err)
	}
	return dir, nil
}

// atomicWriteFile writes data to path, atomically, with the given permissions.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return trace.Wrap(err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return trace.Wrap(err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return trace.Wrap(err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return trace.Wrap(err)
	}
	if err := tmp.Close(); err != nil {
		return trace.Wrap(err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return trace.Wrap(err)
	}
	tmpName = "" // Success, don't remove.
	return nil
}

func loadCreds() ([]storedCredential, error) {
	dir, err := credsDir()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, credsFileName))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, trace.Wrap(err)
	}

	var creds []storedCredential
	if err := json.Unmarshal(b, &creds); err != nil {
		return nil, trace.Wrap(err, "failed to parse %s", filepath.Join(dir, credsFileName))
	}
	return creds, nil
}

func saveCreds(creds []storedCredential) error {
	dir, err := ensureCredsDir()
	if err != nil {
		return trace.Wrap(err)
	}
	b, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return trace.Wrap(err)
	}
	return atomicWriteFile(filepath.Join(dir, credsFileName), b, 0600)
}

// blobFilePath is the root-only sealed blob for a credential.
func blobFilePath(credentialID string) (string, error) {
	dir, err := credsDir()
	if err != nil {
		return "", trace.Wrap(err)
	}
	return filepath.Join(dir, credentialID+".blob"), nil
}

// keyMu guards keyCache, the in-memory copy of the unsealed keys. The plaintext
// never touches the disk: it is sealed at rest as a blob and unsealed into this
// map, which is reset when the daemon exits.
var (
	keyMu    sync.Mutex
	keyCache = make(map[string]*ecdsa.PrivateKey)
)

func cachedKey(credentialID string) *ecdsa.PrivateKey {
	keyMu.Lock()
	defer keyMu.Unlock()
	return keyCache[credentialID]
}

func cacheKey(credentialID string, key *ecdsa.PrivateKey) {
	keyMu.Lock()
	defer keyMu.Unlock()
	keyCache[credentialID] = key
}

func dropCachedKey(credentialID string) {
	keyMu.Lock()
	defer keyMu.Unlock()
	delete(keyCache, credentialID)
}

// saveKey seals the private scalar, verifies the seal round-trips, and writes
// the root-only blob. It fails closed: a blob that cannot be unsealed is never
// persisted.
func saveKey(credentialID string, key *ecdsa.PrivateKey) error {
	if _, err := ensureCredsDir(); err != nil {
		return trace.Wrap(err)
	}
	if key.Curve != elliptic.P256() {
		return trace.BadParameter("unexpected key curve %q", key.Curve.Params().Name)
	}
	scalar, err := scalarBytesPadded(key.D)
	if err != nil {
		return trace.Wrap(err)
	}
	blob, err := verifySealRoundTrip(scalar)
	if err != nil {
		return trace.Wrap(err)
	}
	path, err := blobFilePath(credentialID)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := atomicWriteFile(path, blob, 0600); err != nil {
		return trace.Wrap(err)
	}
	cacheKey(credentialID, key)
	return nil
}

// loadKey returns the credential key from memory, unsealing the blob on first
// use.
func loadKey(credentialID string) (*ecdsa.PrivateKey, error) {
	if key := cachedKey(credentialID); key != nil {
		return key, nil
	}
	path, err := blobFilePath(credentialID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	blob, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrCredentialNotFound
	case err != nil:
		return nil, trace.Wrap(err)
	}
	scalar, err := unsealKeyMaterial(blob)
	if err != nil {
		return nil, trace.Wrap(err, "unseal key")
	}
	key, err := ecdsaFromScalar(scalar)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cacheKey(credentialID, key)
	return key, nil
}

func deleteKey(credentialID string) error {
	dropCachedKey(credentialID)
	path, err := blobFilePath(credentialID)
	if err != nil {
		return trace.Wrap(err)
	}
	switch err := os.Remove(path); {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return trace.Wrap(err)
	}
	return nil
}

// PreloadAllKeys unseals every credential key into memory before the daemon
// starts serving, so a blob that cannot be unsealed makes start-up fail closed
// (seal success does not prove unsealability).
func PreloadAllKeys() error {
	credsMu.Lock()
	defer credsMu.Unlock()

	creds, err := loadCreds()
	if err != nil {
		return trace.Wrap(err)
	}
	for _, c := range creds {
		if _, err := loadKey(c.CredentialID); err != nil {
			return trace.Wrap(err, "credential %q", c.CredentialID)
		}
	}
	logger.InfoContext(context.Background(), "Unsealed touch ID credential keys", "count", len(creds))
	return nil
}

// ImportPlaintextPEM seals a PKCS#8 PEM private key into the store, used by the
// one-time I1a -> I1b migration. The plaintext source file must be removed by
// the caller afterwards.
func ImportPlaintextPEM(credentialID string, pemData []byte) error {
	key, err := parsePKCS8PEM(credentialID, pemData)
	if err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(saveKey(credentialID, key))
}

// parsePKCS8PEM parses a P-256 PKCS#8 PEM private key.
func parsePKCS8PEM(name string, b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != keyPEMType {
		return nil, fmt.Errorf("failed to decode key %q", name)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T in %q", parsed, name)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unexpected key curve %q in %q", key.Curve.Params().Name, name)
	}
	return key, nil
}

func (c storedCredential) info() (*CredentialInfo, error) {
	userHandle, err := base64.RawURLEncoding.DecodeString(c.UserHandle)
	if err != nil {
		return nil, trace.Wrap(err, "failed to decode user handle")
	}
	key, err := loadKey(c.CredentialID)
	if err != nil {
		return nil, trace.Wrap(err, "failed to load key")
	}
	return &CredentialInfo{
		CredentialID: c.CredentialID,
		RPID:         c.RPID,
		User: UserInfo{
			UserHandle: userHandle,
			Name:       c.UserName,
		},
		CreateTime:   c.CreateTime,
		publicKeyRaw: elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
	}, nil
}

// diag returns diagnostics about the Linux touchid backend.
//
// There is no Secure Enclave or code signature to test, so the macOS-specific
// checks are mapped as follows:
//   - HasCompileSupport/HasSignature: always true, this is the touchid build.
//   - HasEntitlements: fprintd is reachable and reports a default device.
//   - PassedLAPolicyTest: fprintd has at least one enrolled fingerprint.
//   - PassedSecureEnclaveTest: the sealed key store is usable, i.e. the system
//     store directory exists and the unseal device is present.
func diag(uid uint32) (*DiagResult, error) {
	res := &DiagResult{
		HasCompileSupport: true,
		HasSignature:      true,
	}

	if _, err := ensureCredsDir(); err != nil {
		logger.WarnContext(context.Background(), "Touch ID credential store is not usable", "error", err)
	} else if _, err := os.Stat(trustedUnsealDevice); err != nil {
		logger.WarnContext(context.Background(), "Touch ID unseal device is not available", "error", err)
	} else {
		res.PassedSecureEnclaveTest = true
	}

	dev, err := newFprintdDevice()
	if err != nil {
		logger.DebugContext(context.Background(), "fprintd is not available", "error", err)
		return res, nil
	}
	res.HasEntitlements = true

	fingers, err := dev.listEnrolledFingers(usernameForUID(uid))
	if err != nil {
		logger.DebugContext(context.Background(), "Failed to list enrolled fingerprints", "error", err)
		return res, nil
	}
	if len(fingers) > 0 {
		res.PassedLAPolicyTest = true
	}

	res.IsAvailable = res.HasEntitlements &&
		res.PassedLAPolicyTest &&
		res.PassedSecureEnclaveTest
	return res, nil
}

// registerCredential creates a new software P-256 credential. It does not
// require user presence; the WebAuthn registration flow performs the
// attestation signature, which does.
func registerCredential(rpID, user string, userHandle []byte) (*CredentialInfo, error) {
	if rpID == "" {
		return nil, trace.BadParameter("rpID required")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	credentialID := uuid.NewString()
	if err := saveKey(credentialID, key); err != nil {
		return nil, trace.Wrap(err)
	}

	credsMu.Lock()
	defer credsMu.Unlock()

	creds, err := loadCreds()
	if err != nil {
		_ = deleteKey(credentialID)
		return nil, trace.Wrap(err)
	}
	creds = append(creds, storedCredential{
		CredentialID: credentialID,
		RPID:         rpID,
		UserName:     user,
		UserHandle:   base64.RawURLEncoding.EncodeToString(userHandle),
		CreateTime:   time.Now(),
	})
	if err := saveCreds(creds); err != nil {
		_ = deleteKey(credentialID)
		return nil, trace.Wrap(err)
	}

	return &CredentialInfo{
		CredentialID: credentialID,
		publicKeyRaw: elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
	}, nil
}

// findCredentialInfos finds credentials without user interaction.
// An empty user means "all users".
func findCredentialInfos(rpID, user string) ([]CredentialInfo, error) {
	credsMu.Lock()
	defer credsMu.Unlock()

	creds, err := loadCreds()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	infos := make([]CredentialInfo, 0, len(creds))
	for _, c := range creds {
		if c.RPID != rpID {
			continue
		}
		if user != "" && c.UserName != user {
			continue
		}
		info, err := c.info()
		if err != nil {
			logger.WarnContext(context.Background(), "Skipping credential", "credential_id", c.CredentialID, "error", err)
			continue
		}
		infos = append(infos, *info)
	}
	return infos, nil
}

// listCredentialInfos lists all credentials without user interaction.
func listCredentialInfos() ([]CredentialInfo, error) {
	credsMu.Lock()
	defer credsMu.Unlock()

	creds, err := loadCreds()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	infos := make([]CredentialInfo, 0, len(creds))
	for _, c := range creds {
		info, err := c.info()
		if err != nil {
			logger.WarnContext(context.Background(), "Skipping credential", "credential_id", c.CredentialID, "error", err)
			continue
		}
		infos = append(infos, *info)
	}
	return infos, nil
}

// loadAndSign signs digest with the credential key. It does not itself ask for
// user presence; callers are expected to have verified it already.
func loadAndSign(credentialID string, digest []byte) ([]byte, error) {
	key, err := loadKey(credentialID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	return sig, trace.Wrap(err)
}

// deleteCredentialNonInteractive deletes a credential without user interaction.
func deleteCredentialNonInteractive(credentialID string) error {
	if credentialID == "" {
		return trace.BadParameter("credentialID required")
	}

	credsMu.Lock()
	defer credsMu.Unlock()

	creds, err := loadCreds()
	if err != nil {
		return trace.Wrap(err)
	}

	found := false
	remaining := creds[:0]
	for _, c := range creds {
		if c.CredentialID == credentialID {
			found = true
			continue
		}
		remaining = append(remaining, c)
	}
	if !found {
		return ErrCredentialNotFound
	}
	if err := saveCreds(remaining); err != nil {
		return trace.Wrap(err)
	}
	return deleteKey(credentialID)
}

// signService is the stateful daemon side of the helper. It enforces user
// presence (with the macOS-parity reuse window) around the credential-store
// operations above, keyed by the SO_PEERCRED uid of the calling connection.
type signService struct {
	// verifyMu serializes presence checks, so concurrent connections don't
	// stack up fprintd prompts.
	verifyMu sync.Mutex
	// verifiedAt records when presence was last confirmed, per uid and scope:
	// an approval covers only the operation it was shown for (one credential,
	// listing, ...), so a dialog for credential A never silently authorizes B.
	verifiedAt map[presenceKey]time.Time

	mu            sync.Mutex
	nextContextID int
	contexts      map[int]uint32
}

func newSignService() *signService {
	return &signService{
		verifiedAt: make(map[presenceKey]time.Time),
		contexts:   make(map[int]uint32),
	}
}

// verifyPresence is the user-presence check used by signService: the polkit
// dialog, with the fprintd check as the fallback (see polkit_linux.go). It is
// a package variable so tests can substitute a fake presence check.
var verifyPresence = verifyPolkitOrFingerprint

// presenceKey scopes the reuse window.
type presenceKey struct {
	uid   uint32
	scope string
}

// ensureVerified asks for user presence unless a verification for the same
// uid and scope (peer.Scope) happened within the reuse window. It fails
// closed.
func (s *signService) ensureVerified(peer PresencePeer) error {
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()

	key := presenceKey{uid: peer.UID, scope: peer.Scope}
	if t, ok := s.verifiedAt[key]; ok && time.Since(t) < fingerprintReuseWindow {
		logger.DebugContext(context.Background(), "Reusing presence verification", "uid", peer.UID, "scope", peer.Scope)
		return nil
	}
	if err := verifyPresence(context.Background(), peer); err != nil {
		return trace.Wrap(err)
	}
	s.verifiedAt[key] = time.Now()
	return nil
}

// register creates a credential after a presence check, so a label can only
// appear in a later dialog after the user approved its registration. The
// scope is per registration request, so it never reuses (or opens) a window
// for an existing credential.
func (s *signService) register(peer PresencePeer, rpID, user string, userHandle []byte) (*CredentialInfo, error) {
	peer.Reason = "registering " + user + "@" + rpID
	peer.Scope = "register:" + user + "@" + rpID
	if err := s.ensureVerified(peer); err != nil {
		return nil, trace.Wrap(err)
	}
	info, err := registerCredential(rpID, user, userHandle)
	return info, trace.Wrap(err)
}

// newAuthContext allocates a context for uid and returns its ID.
func (s *signService) newAuthContext(uid uint32) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextContextID++
	s.contexts[s.nextContextID] = uid
	return s.nextContextID
}

// closeAuthContext drops a context. It is a no-op if the ID is unknown.
func (s *signService) closeAuthContext(contextID int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, contextID)
}

// authContextUID returns the uid a context belongs to, if it exists.
func (s *signService) authContextUID(contextID int) (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid, ok := s.contexts[contextID]
	return uid, ok
}

// credentialLabel names a stored credential as "<user>@<rp id>" for the
// presence dialog. It fails for an unknown credential, before any prompt.
func credentialLabel(credentialID string) (string, error) {
	credsMu.Lock()
	defer credsMu.Unlock()
	creds, err := loadCreds()
	if err != nil {
		return "", trace.Wrap(err)
	}
	for _, c := range creds {
		if c.CredentialID == credentialID {
			return c.UserName + "@" + c.RPID, nil
		}
	}
	return "", trace.NotFound("credential %q not found", credentialID)
}

func (s *signService) authenticate(peer PresencePeer, credentialID string, digest []byte) ([]byte, error) {
	label, err := credentialLabel(credentialID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	peer.Reason = label
	peer.Scope = "credential:" + credentialID
	if err := s.ensureVerified(peer); err != nil {
		return nil, trace.Wrap(err)
	}
	return loadAndSign(credentialID, digest)
}

func (s *signService) listCredentials(peer PresencePeer) ([]CredentialInfo, error) {
	// Match macOS semantics: listing requires user interaction (the presence
	// prompt), even though the metadata itself is a regular user-owned file.
	peer.Reason = "listing Touch ID credentials"
	peer.Scope = "list"
	if err := s.ensureVerified(peer); err != nil {
		return nil, trace.Wrap(err)
	}
	return listCredentialInfos()
}

func (s *signService) deleteCredential(peer PresencePeer, credentialID string) error {
	// Match macOS semantics: deletion requires user interaction.
	label, err := credentialLabel(credentialID)
	if err != nil {
		return trace.Wrap(err)
	}
	peer.Reason = "deleting " + label
	peer.Scope = "delete:" + credentialID
	if err := s.ensureVerified(peer); err != nil {
		return trace.Wrap(err)
	}
	return deleteCredentialNonInteractive(credentialID)
}

// fprintdDevice is a handle to an fprintd D-Bus device.
type fprintdDevice struct {
	conn *dbus.Conn
	path dbus.ObjectPath
	name string
}

func newFprintdDevice() (*fprintdDevice, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, trace.Wrap(err, "failed to connect to the D-Bus system bus")
	}

	mgr := conn.Object(fprintdBusName, fprintdManagerPath)
	var path dbus.ObjectPath
	if err := mgr.Call(fprintdManagerIface+".GetDefaultDevice", 0).Store(&path); err != nil {
		return nil, trace.Wrap(err, "failed to get the default fingerprint device")
	}
	if path == "" || path == "/" {
		return nil, errors.New("no fingerprint device found")
	}

	dev := conn.Object(fprintdBusName, path)
	var props map[string]dbus.Variant
	if err := dev.Call("org.freedesktop.DBus.Properties.GetAll", 0, fprintdDeviceIface).Store(&props); err != nil {
		return nil, trace.Wrap(err, "failed to get fingerprint device properties")
	}
	name, _ := props["name"].Value().(string)

	return &fprintdDevice{
		conn: conn,
		path: path,
		name: name,
	}, nil
}

// usernameForUID maps a client uid to the fprintd username argument. When the
// caller uid is the daemon's own uid (the unprivileged dev shape), an empty
// string maps to the caller's session user without requiring the "setusername"
// polkit action. When the daemon runs as a different uid (root in the hardened
// shape), fprintd needs the explicit target username, which root is allowed to
// pass (S4).
func usernameForUID(uid uint32) string {
	if uid == uint32(os.Geteuid()) {
		return ""
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		logger.WarnContext(context.Background(), "Failed to resolve uid for fingerprint verification", "uid", uid, "error", err)
		return ""
	}
	return u.Username
}

func (d *fprintdDevice) listEnrolledFingers(username string) ([]string, error) {
	call := d.conn.Object(fprintdBusName, d.path).Call(fprintdDeviceIface+".ListEnrolledFingers", 0, username)
	if call.Err != nil {
		return nil, trace.Wrap(call.Err)
	}
	var fingers []string
	if err := call.Store(&fingers); err != nil {
		return nil, trace.Wrap(err)
	}
	return fingers, nil
}

// errFingerprintDevice is a transient capture failure, worth retrying.
var errFingerprintDevice = errors.New("fingerprint device error")

// fprintdMu serializes fingerprint verifications within the process.
var fprintdMu sync.Mutex

// verify asks the user for a fingerprint and blocks until the verification
// succeeds, fails or times out. username is the account whose prints are
// checked; an empty string means the caller's session user.
func (d *fprintdDevice) verify(ctx context.Context, username string) error {
	fprintdMu.Lock()
	defer fprintdMu.Unlock()

	obj := d.conn.Object(fprintdBusName, d.path)
	if err := obj.Call(fprintdDeviceIface+".Claim", 0, username).Err; err != nil {
		return trace.Wrap(err, "failed to claim the fingerprint device")
	}
	defer func() {
		if err := obj.Call(fprintdDeviceIface+".Release", 0).Err; err != nil {
			logger.DebugContext(ctx, "Failed to release the fingerprint device", "error", err)
		}
	}()

	// Subscribe to signals before starting the verification, otherwise the
	// first status can be missed.
	sigs := make(chan *dbus.Signal, 16)
	d.conn.Signal(sigs)
	defer d.conn.RemoveSignal(sigs)

	matchOpts := []dbus.MatchOption{
		dbus.WithMatchObjectPath(d.path),
		dbus.WithMatchInterface(fprintdDeviceIface),
	}
	if err := d.conn.AddMatchSignal(matchOpts...); err != nil {
		return trace.Wrap(err, "failed to subscribe to fprintd signals")
	}
	defer func() {
		if err := d.conn.RemoveMatchSignal(matchOpts...); err != nil {
			logger.DebugContext(ctx, "Failed to remove fprintd match rule", "error", err)
		}
	}()

	deadline := time.Now().Add(fingerprintVerifyTimeout)
	var lastErr error
	for attempt := 1; attempt <= fingerprintVerifyAttempts; attempt++ {
		// Drop any status left over from a previous attempt.
		for draining := true; draining; {
			select {
			case <-sigs:
			default:
				draining = false
			}
		}

		logger.DebugContext(ctx, "Prompting for fingerprint", "device", d.name, "attempt", attempt)
		if err := obj.Call(fprintdDeviceIface+".VerifyStart", 0, "any").Err; err != nil {
			return trace.Wrap(err, "failed to start fingerprint verification")
		}

		err := waitVerifyStatus(ctx, sigs, d.path, deadline)
		if stopErr := obj.Call(fprintdDeviceIface+".VerifyStop", 0).Err; stopErr != nil {
			logger.DebugContext(ctx, "Failed to stop fingerprint verification", "error", stopErr)
		}

		switch {
		case err == nil:
			return nil
		case errors.Is(err, errFingerprintDevice) && attempt < fingerprintVerifyAttempts:
			logger.DebugContext(ctx, "Fingerprint capture failed, retrying", "attempt", attempt, "error", err)
			lastErr = err
			continue
		default:
			return err
		}
	}
	return lastErr
}

// waitVerifyStatus waits for a terminal VerifyStatus signal.
func waitVerifyStatus(ctx context.Context, sigs <-chan *dbus.Signal, path dbus.ObjectPath, deadline time.Time) error {
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return errors.New("timed out waiting for a fingerprint")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case sig, ok := <-sigs:
			if !ok {
				return errors.New("fprintd signal channel closed")
			}
			if sig.Path != path || sig.Name != fprintdDeviceIface+".VerifyStatus" || len(sig.Body) == 0 {
				continue
			}
			status, _ := sig.Body[0].(string)
			switch status {
			case "verify-match":
				return nil
			case "verify-no-match":
				return errors.New("fingerprint does not match")
			case "verify-disconnected":
				return errors.New("fingerprint device disconnected")
			case "verify-unknown-error":
				return errFingerprintDevice
			default:
				// Retry statuses (verify-retry-scan, verify-swipe-too-short,
				// verify-finger-not-centered, verify-remove-and-retry,
				// verify-too-fast) mean the verification is still ongoing.
				logger.DebugContext(ctx, "Fingerprint verification status", "status", status)
			}
		case <-timer.C:
			return errors.New("timed out waiting for a fingerprint")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func verifyFingerprint(ctx context.Context, uid uint32) error {
	dev, err := newFprintdDevice()
	if err != nil {
		return trace.Wrap(err)
	}
	return dev.verify(ctx, usernameForUID(uid))
}
