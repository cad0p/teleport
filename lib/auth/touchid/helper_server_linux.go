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

// systemHelperSocketPath is the hardened, system-wide socket used by the
// privileged daemon.
const systemHelperSocketPath = "/run/tsh-touchid/helper.sock"

// helperSocketPath returns the AF_UNIX socket the helper daemon listens on.
//
// The system socket takes precedence when present (the hardened daemon shape);
// otherwise it falls back to the per-user dev socket. $TSH_TOUCHID_SOCKET wins
// over both, for tests and non-standard layouts.
func helperSocketPath() (string, error) {
	if p := os.Getenv("TSH_TOUCHID_SOCKET"); p != "" {
		return p, nil
	}
	if _, err := os.Stat(systemHelperSocketPath); err == nil {
		return systemHelperSocketPath, nil
	}
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
// by the caller. Without a peer pidfd, presence checks use fprintd only; the
// daemon uses ServePeer.
func (s *HelperServer) ServeConn(conn net.Conn, uid uint32) error {
	return s.ServePeer(conn, PresencePeer{UID: uid, PIDFD: -1})
}

// ServePeer handles a single client connection whose peer has been identified
// by the caller (SO_PEERCRED uid, already validated, plus an optional pidfd
// that stays owned by the caller). It returns when the client disconnects.
func (s *HelperServer) ServePeer(conn net.Conn, peer PresencePeer) error {
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

		result, err := s.dispatch(peer, &req)
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
func (s *HelperServer) dispatch(peer PresencePeer, req *helperRequest) (any, error) {
	uid := peer.UID
	switch req.Method {
	case helperMethodDiag:
		res, err := diag(uid)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return diagResultFromCore(res), nil

	case helperMethodRegister:
		var params registerParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid Register params")
		}
		info, err := s.svc.register(peer, params.RPID, params.User, params.UserHandle)
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
		if params.ContextID != 0 {
			if err := s.checkContextOwner(params.ContextID, uid); err != nil {
				return nil, trace.Wrap(err)
			}
		}
		sig, err := s.svc.authenticate(peer, params.CredentialID, params.Digest)
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
		infos, err := s.svc.listCredentials(peer)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return listCredentialsResult{Credentials: credentialInfosToProtocol(infos)}, nil

	case helperMethodDeleteCredential:
		var params deleteCredentialParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid DeleteCredential params")
		}
		return nil, trace.Wrap(s.svc.deleteCredential(peer, params.CredentialID))

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
		if err := s.checkContextOwner(params.ContextID, uid); err != nil {
			return nil, trace.Wrap(err)
		}
		peer.Reason = "choosing a Teleport user"
		peer.Scope = "guard"
		return nil, trace.Wrap(s.svc.ensureVerified(peer))

	case helperMethodAuthContextClose:
		var params authContextCloseParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, trace.Wrap(err, "invalid AuthContextClose params")
		}
		if err := s.checkContextOwner(params.ContextID, uid); err != nil {
			return nil, trace.Wrap(err)
		}
		s.svc.closeAuthContext(params.ContextID)
		return nil, nil

	default:
		return nil, trace.Errorf("unknown method: %q", req.Method)
	}
}

// checkContextOwner refuses an auth context that does not exist or that was
// created by another uid: presence is checked for, and recorded against, the
// connection's own peer, so a context must not carry another user's identity.
func (s *HelperServer) checkContextOwner(contextID int, uid uint32) error {
	owner, ok := s.svc.authContextUID(contextID)
	if !ok {
		return trace.Errorf("auth context %d not found", contextID)
	}
	if owner != uid {
		return trace.AccessDenied("auth context %d belongs to another user", contextID)
	}
	return nil
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
