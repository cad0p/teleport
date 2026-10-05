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

// Linux helper daemon: JSON-RPC over an AF_UNIX socket.
//
// The daemon owns the credential store and talks to fprintd; the tsh process
// only ever sends a digest and receives a signature, so the private key stays
// in the daemon. The socket lives in $XDG_RUNTIME_DIR and is 0600; every
// connection is additionally checked against the daemon's configured uid via
// SO_PEERCRED.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gravitational/trace"
)

// helperSocketName is the AF_UNIX socket file name.
const helperSocketName = "tsh-touchid.sock"

// helperSocketPath returns the AF_UNIX socket the helper daemon listens on.
//
// It prefers $XDG_RUNTIME_DIR/tsh-touchid.sock; when XDG_RUNTIME_DIR is unset
// (e.g. a bare SSH session) it falls back to the credential directory, which is
// still a per-user 0700 directory.
func helperSocketPath() (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, helperSocketName), nil
	}
	dir, err := credsDir()
	if err != nil {
		return "", trace.Wrap(err)
	}
	return filepath.Join(dir, helperSocketName), nil
}

// HelperSocketPath is the exported form of helperSocketPath, for the daemon
// binary.
func HelperSocketPath() (string, error) {
	return helperSocketPath()
}

// HelperServer is the touchid helper daemon server. One instance is shared by
// all connections so the presence reuse window spans them.
type HelperServer struct {
	svc *signService
}

// NewHelperServer creates a helper server.
func NewHelperServer() *HelperServer {
	return &HelperServer{svc: newSignService()}
}

// ServeConn handles a single client connection. It returns when the client
// disconnects. uid is the SO_PEERCRED uid of the connection, already validated
// by the caller.
func (s *HelperServer) ServeConn(conn net.Conn, uid uint32) error {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var req helperRequest
		if err := json.Unmarshal(line, &req); err != nil {
			logger.WarnContext(context.Background(), "Discarding malformed helper request", "error", err)
			continue
		}

		result, err := s.dispatch(uid, &req)
		resp := helperResponse{ID: req.ID}
		switch {
		case err != nil:
			resp.Error = err.Error()
		case result != nil:
			b, mErr := json.Marshal(result)
			if mErr != nil {
				resp.Error = mErr.Error()
			} else {
				raw := json.RawMessage(b)
				resp.Result = &raw
			}
		default:
			empty := json.RawMessage("{}")
			resp.Result = &empty
		}

		if err := enc.Encode(resp); err != nil {
			return trace.Wrap(err, "writing helper response")
		}
	}
	return trace.Wrap(scanner.Err())
}

// dispatch runs a single request and returns the result to marshal (nil for
// methods with an empty result).
func (s *HelperServer) dispatch(uid uint32, req *helperRequest) (any, error) {
	switch req.Method {
	case helperMethodDiag:
		res, err := diag()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return diagResultFromCore(res), nil

	case helperMethodRegister:
		var params registerParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid Register params")
		}
		info, err := registerCredential(params.RPID, params.User, params.UserHandle)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return registerResult{
			CredentialID: info.CredentialID,
			PubKeyRaw:    info.publicKeyRaw,
		}, nil

	case helperMethodAuthenticate:
		var params authenticateParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid Authenticate params")
		}
		contextUID := uid
		if params.ContextID != 0 {
			cu, ok := s.svc.authContextUID(params.ContextID)
			if !ok {
				return nil, trace.Errorf("auth context %d not found", params.ContextID)
			}
			contextUID = cu
		}
		sig, err := s.svc.authenticate(contextUID, params.CredentialID, params.Digest)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return authenticateResult{Signature: sig}, nil

	case helperMethodFindCredentials:
		var params findCredentialsParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid FindCredentials params")
		}
		infos, err := findCredentialInfos(params.RPID, params.User)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return findCredentialsResult{Credentials: credentialInfosToProtocol(infos)}, nil

	case helperMethodListCredentials:
		infos, err := s.svc.listCredentials(uid)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return listCredentialsResult{Credentials: credentialInfosToProtocol(infos)}, nil

	case helperMethodDeleteCredential:
		var params deleteCredentialParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid DeleteCredential params")
		}
		return nil, trace.Wrap(s.svc.deleteCredential(uid, params.CredentialID))

	case helperMethodDeleteNonInteractive:
		var params deleteNonInteractiveParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid DeleteNonInteractive params")
		}
		return nil, trace.Wrap(deleteCredentialNonInteractive(params.CredentialID))

	case helperMethodNewAuthContext:
		return newAuthContextResult{ContextID: s.svc.newAuthContext(uid)}, nil

	case helperMethodAuthContextGuard:
		var params authContextGuardParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid AuthContextGuard params")
		}
		contextUID, ok := s.svc.authContextUID(params.ContextID)
		if !ok {
			return nil, trace.Errorf("auth context %d not found", params.ContextID)
		}
		return nil, trace.Wrap(s.svc.ensureVerified(contextUID))

	case helperMethodAuthContextClose:
		var params authContextCloseParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid AuthContextClose params")
		}
		s.svc.closeAuthContext(params.ContextID)
		return nil, nil

	default:
		return nil, trace.Errorf("unknown method: %q", req.Method)
	}
}

func diagResultFromCore(d *DiagResult) diagResult {
	return diagResult{
		HasSignature:            d.HasSignature,
		HasEntitlements:         d.HasEntitlements,
		PassedLAPolicyTest:      d.PassedLAPolicyTest,
		PassedSecureEnclaveTest: d.PassedSecureEnclaveTest,
		IsAvailable:             d.IsAvailable,
	}
}

func credentialInfosToProtocol(infos []CredentialInfo) []credentialInfo {
	out := make([]credentialInfo, 0, len(infos))
	for i := range infos {
		out = append(out, credentialInfo{
			CredentialID: infos[i].CredentialID,
			RPID:         infos[i].RPID,
			UserName:     infos[i].User.Name,
			UserHandle:   infos[i].User.UserHandle,
			PubKeyRaw:    infos[i].publicKeyRaw,
			CreateTime:   infos[i].CreateTime.Format(time.RFC3339),
		})
	}
	return out
}
