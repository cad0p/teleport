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

// Linux client implementation of the nativeTID interface.
//
// It is a thin client of the tsh-touchid-helper daemon: it never touches the
// private key, nor fprintd. It speaks the same line-delimited JSON-RPC as the
// macOS helper (PR #64128), just over an AF_UNIX socket instead of stdio.

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/gravitational/trace"
)

// helperBinaryName is the helper daemon binary name.
const helperBinaryName = "tsh-touchid-helper"

// helperNative implements nativeTID by proxying calls to the helper daemon.
type helperNative struct {
	mu   sync.Mutex // serializes requests; a single connection is shared
	conn net.Conn
	enc  *json.Encoder
	dec  *bufio.Scanner

	nextID int
}

// native is the Linux implementation of the nativeTID interface. It is a client
// of the helper daemon, which owns the credential store and fprintd presence.
var native nativeTID = &helperNative{}

// connectLocked dials the helper socket if not already connected.
// h.mu must be held.
func (h *helperNative) connectLocked() error {
	if h.conn != nil {
		return nil
	}
	path, err := helperSocketPath()
	if err != nil {
		return trace.Wrap(err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return trace.Wrap(err, "touch ID helper is not running (start %s on %s)", helperBinaryName, path)
	}
	h.conn = conn
	h.enc = json.NewEncoder(conn)
	h.dec = bufio.NewScanner(conn)
	h.dec.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return nil
}

// resetLocked drops a broken connection so the next request reconnects.
// h.mu must be held.
func (h *helperNative) resetLocked() {
	if h.conn != nil {
		_ = h.conn.Close()
	}
	h.conn = nil
	h.enc = nil
	h.dec = nil
}

// sendRequest performs one JSON-RPC round trip with the helper daemon.
func (h *helperNative) sendRequest(method string, params any, result any) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := h.connectLocked(); err != nil {
		return trace.Wrap(err)
	}

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return trace.Wrap(err, "helper: marshal params")
		}
		rawParams = b
	}

	h.nextID++
	req := helperRequest{
		ID:     h.nextID,
		Method: method,
		Params: rawParams,
	}
	if err := h.enc.Encode(req); err != nil {
		h.resetLocked()
		return trace.Wrap(err, "helper: write request")
	}

	if !h.dec.Scan() {
		err := h.dec.Err()
		h.resetLocked()
		if err != nil {
			return trace.Wrap(err, "helper: read response")
		}
		return trace.Wrap(ErrNotAvailable, "helper: daemon closed the connection")
	}

	var resp helperResponse
	if err := json.Unmarshal(h.dec.Bytes(), &resp); err != nil {
		return trace.Wrap(err, "helper: decode response")
	}
	if resp.Error != "" {
		return trace.Errorf("helper: %s", resp.Error)
	}
	if result != nil && resp.Result != nil {
		if err := json.Unmarshal(*resp.Result, result); err != nil {
			return trace.Wrap(err, "helper: decode result")
		}
	}
	return nil
}

// Diag implements nativeTID.
func (h *helperNative) Diag() (*DiagResult, error) {
	var result diagResult
	if err := h.sendRequest(helperMethodDiag, nil, &result); err != nil {
		return nil, trace.Wrap(err)
	}
	return &DiagResult{
		HasCompileSupport:       true,
		HasSignature:            result.HasSignature,
		HasEntitlements:         result.HasEntitlements,
		PassedLAPolicyTest:      result.PassedLAPolicyTest,
		PassedSecureEnclaveTest: result.PassedSecureEnclaveTest,
		IsAvailable:             result.IsAvailable,
	}, nil
}

// NewAuthContext implements nativeTID.
func (h *helperNative) NewAuthContext() AuthContext {
	var result newAuthContextResult
	if err := h.sendRequest(helperMethodNewAuthContext, nil, &result); err != nil {
		// The interface cannot return an error here; return a context that
		// fails on Guard.
		return &helperAuthContext{h: h, contextID: -1}
	}
	return &helperAuthContext{h: h, contextID: result.ContextID}
}

// Register implements nativeTID.
func (h *helperNative) Register(rpID, user string, userHandle []byte) (*CredentialInfo, error) {
	params := registerParams{
		RPID:       rpID,
		User:       user,
		UserHandle: userHandle,
	}
	var result registerResult
	if err := h.sendRequest(helperMethodRegister, &params, &result); err != nil {
		return nil, trace.Wrap(err)
	}
	return &CredentialInfo{
		CredentialID: result.CredentialID,
		publicKeyRaw: result.PubKeyRaw,
	}, nil
}

// Authenticate implements nativeTID.
func (h *helperNative) Authenticate(actx AuthContext, credentialID string, digest []byte) ([]byte, error) {
	var contextID int
	if hctx, ok := actx.(*helperAuthContext); ok {
		contextID = hctx.contextID
	}
	params := authenticateParams{
		ContextID:    contextID,
		CredentialID: credentialID,
		Digest:       digest,
	}
	var result authenticateResult
	if err := h.sendRequest(helperMethodAuthenticate, &params, &result); err != nil {
		return nil, trace.Wrap(err)
	}
	return result.Signature, nil
}

// FindCredentials implements nativeTID.
func (h *helperNative) FindCredentials(rpID, user string) ([]CredentialInfo, error) {
	params := findCredentialsParams{
		RPID: rpID,
		User: user,
	}
	var result findCredentialsResult
	if err := h.sendRequest(helperMethodFindCredentials, &params, &result); err != nil {
		return nil, trace.Wrap(err)
	}
	return convertCredentialInfos(result.Credentials)
}

// ListCredentials implements nativeTID.
func (h *helperNative) ListCredentials() ([]CredentialInfo, error) {
	var result listCredentialsResult
	if err := h.sendRequest(helperMethodListCredentials, nil, &result); err != nil {
		return nil, trace.Wrap(err)
	}
	return convertCredentialInfos(result.Credentials)
}

// DeleteCredential implements nativeTID.
func (h *helperNative) DeleteCredential(credentialID string) error {
	return h.sendRequest(helperMethodDeleteCredential, &deleteCredentialParams{
		CredentialID: credentialID,
	}, nil)
}

// DeleteNonInteractive implements nativeTID.
func (h *helperNative) DeleteNonInteractive(credentialID string) error {
	return h.sendRequest(helperMethodDeleteNonInteractive, &deleteNonInteractiveParams{
		CredentialID: credentialID,
	}, nil)
}

// convertCredentialInfos converts protocol credentialInfo slices to package
// CredentialInfo slices, parsing create_time from RFC3339.
func convertCredentialInfos(creds []credentialInfo) ([]CredentialInfo, error) {
	infos := make([]CredentialInfo, 0, len(creds))
	for _, c := range creds {
		var createTime time.Time
		if c.CreateTime != "" {
			var err error
			createTime, err = time.Parse(time.RFC3339, c.CreateTime)
			if err != nil {
				// Best-effort: log but don't fail.
				logger.WarnContext(context.Background(), "Failed to parse create_time from helper",
					"create_time", c.CreateTime,
					"error", err,
				)
			}
		}
		infos = append(infos, CredentialInfo{
			CredentialID: c.CredentialID,
			RPID:         c.RPID,
			User: UserInfo{
				UserHandle: c.UserHandle,
				Name:       c.UserName,
			},
			CreateTime:   createTime,
			publicKeyRaw: c.PubKeyRaw,
		})
	}
	return infos, nil
}

// helperAuthContext is an AuthContext backed by the helper daemon. The daemon
// enforces the presence reuse window; the context only carries the ID.
type helperAuthContext struct {
	h         *helperNative
	contextID int
}

// Guard implements AuthContext. It asks the daemon to verify presence, then
// runs fn locally.
func (c *helperAuthContext) Guard(fn func()) error {
	if c.contextID < 0 {
		return trace.Wrap(ErrNotAvailable)
	}
	if err := c.h.sendRequest(helperMethodAuthContextGuard, &authContextGuardParams{
		ContextID: c.contextID,
	}, nil); err != nil {
		return trace.Wrap(err)
	}
	fn()
	return nil
}

// Close implements AuthContext.
func (c *helperAuthContext) Close() {
	if c.contextID < 0 {
		return
	}
	// Best-effort.
	_ = c.h.sendRequest(helperMethodAuthContextClose, &authContextCloseParams{
		ContextID: c.contextID,
	}, nil)
}
