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

// tsh-touchid-helper is the Linux Touch ID helper daemon. It owns the P-256
// credentials, keeps them SEP-sealed at rest, and performs user presence via
// fprintd, exposing the same JSON-RPC protocol as the macOS helper (PR #64128)
// over an AF_UNIX socket.
//
// In the hardened shape it runs as root: the system socket lives at
// /run/tsh-touchid/helper.sock and the sealed blobs under /var/lib/tsh-touchid.
// Every connection is checked against an explicit uid allow-list via
// SO_PEERCRED, and the keys are unsealed into memory at start-up (fail closed).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gravitational/teleport/lib/auth/touchid"
)

const systemSocketPath = "/run/tsh-touchid/helper.sock"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "seal-pem" {
		sealPEM(os.Args[2:])
		return
	}
	runDaemon(os.Args[1:])
}

// sealPEM is the one-time I1a -> I1b migration: seal a plaintext PKCS#8 PEM into
// the store and verify the seal round-trips. It is run as root by the install
// script; the caller removes the plaintext source afterwards.
func sealPEM(args []string) {
	fs := flag.NewFlagSet("seal-pem", flag.ExitOnError)
	store := fs.String("store", "", "credential store directory (required)")
	pemPath := fs.String("pem", "", "path to the PKCS#8 PEM key (required)")
	credID := fs.String("id", "", "credential id (default: the PEM file base name)")
	_ = fs.Parse(args)

	if *store == "" || *pemPath == "" {
		fatal(errors.New("seal-pem: -store and -pem are required"))
	}
	id := *credID
	if id == "" {
		id = strings.TrimSuffix(filepath.Base(*pemPath), filepath.Ext(*pemPath))
	}

	data, err := os.ReadFile(*pemPath)
	if err != nil {
		fatal(fmt.Errorf("seal-pem: read %s: %w", *pemPath, err))
	}

	touchid.SetStoreDir(*store)
	if err := touchid.ImportPlaintextPEM(id, data); err != nil {
		fatal(fmt.Errorf("seal-pem: %s: %w", id, err))
	}
	fmt.Printf("sealed id=%s blob=%s round_trip=ok\n", id, filepath.Join(*store, id+".blob"))
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("tsh-touchid-helper", flag.ExitOnError)
	socketFlag := fs.String("socket", "", "AF_UNIX socket path (default: the system socket as root, the per-user socket otherwise)")
	uidsFlag := fs.String("allowed-uids", "", "comma-separated uids allowed to connect (default: the daemon's own uid)")
	storeFlag := fs.String("store", "", "credential store directory (default: the user config dir)")
	unsealTimeout := fs.Duration("unseal-timeout", touchid.DefaultSEPReadyTimeout, "bound on waiting for the SEP key store and retrying the credential unseal at start-up before failing closed")
	_ = fs.Parse(args)

	if *storeFlag != "" {
		touchid.SetStoreDir(*storeFlag)
	}

	allowed, err := parseAllowedUIDs(*uidsFlag, uint32(os.Getuid()))
	if err != nil {
		fatal(err)
	}

	socketPath := *socketFlag
	if socketPath == "" {
		if os.Geteuid() == 0 {
			socketPath = systemSocketPath
		} else {
			p, err := touchid.HelperSocketPath()
			if err != nil {
				fatal(err)
			}
			socketPath = p
		}
	}

	// The socket directory must not be writable by anyone but root, otherwise
	// the socket could be swapped; the socket itself is connectable because
	// SO_PEERCRED, not the file mode, is the access control.
	socketDirMode := os.FileMode(0700)
	socketMode := os.FileMode(0600)
	if os.Geteuid() == 0 {
		socketDirMode = 0755
		socketMode = 0666
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), socketDirMode); err != nil {
		fatal(fmt.Errorf("create socket dir: %w", err))
	}
	if err := os.Chmod(filepath.Dir(socketPath), socketDirMode); err != nil {
		fatal(fmt.Errorf("chmod socket dir: %w", err))
	}

	// Unseal every credential before serving so a blob that cannot be unsealed
	// stops the daemon (fail closed). At boot the SEP key store may still be
	// coming up, so wait on the driver's readiness signal and retry with
	// backoff instead of relying on systemd restarts.
	log.Printf("unsealing credential store (up to %s)", *unsealTimeout)
	if err := touchid.UnsealWithBackoff(*unsealTimeout); err != nil {
		fatal(fmt.Errorf("failed to unseal credential keys (fail closed): %w", err))
	}

	// Refuse to stomp on a running daemon; remove a stale socket otherwise.
	if _, err := os.Stat(socketPath); err == nil {
		if c, derr := net.Dial("unix", socketPath); derr == nil {
			_ = c.Close()
			fatal(fmt.Errorf("helper already running at %s", socketPath))
		}
		if err := os.Remove(socketPath); err != nil {
			fatal(fmt.Errorf("remove stale socket: %w", err))
		}
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		fatal(fmt.Errorf("listen on %s: %w", socketPath, err))
	}
	if err := os.Chmod(socketPath, socketMode); err != nil {
		fatal(fmt.Errorf("chmod socket: %w", err))
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("tsh-touchid-helper listening on %s (uid %d, allowed %v)", socketPath, os.Getuid(), allowed)

	// Clean up the socket on shutdown.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigc
		log.Printf("received %s, shutting down", sig)
		_ = listener.Close()
		_ = os.Remove(socketPath)
		os.Exit(0)
	}()

	srv := touchid.NewHelperServer()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}

		uid, err := peerUID(conn)
		if err != nil {
			log.Printf("rejecting connection: peer uid unknown: %v", err)
			_ = conn.Close()
			continue
		}
		if !allowed[uid] {
			log.Printf("rejecting connection from uid %d (allowed %v)", uid, allowed)
			_ = conn.Close()
			continue
		}

		go func(c *net.UnixConn, u uint32) {
			if err := srv.ServeConn(c, u); err != nil {
				log.Printf("connection closed: %v", err)
			}
		}(conn, uid)
	}
}

// parseAllowedUIDs parses a comma-separated uid allow-list. An empty list means
// "only the daemon's own uid".
func parseAllowedUIDs(s string, ownUID uint32) (map[uint32]bool, error) {
	if strings.TrimSpace(s) == "" {
		return map[uint32]bool{ownUID: true}, nil
	}
	out := make(map[uint32]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid uid %q: %w", part, err)
		}
		out[uint32(v)] = true
	}
	if len(out) == 0 {
		return nil, errors.New("allowed-uids is empty")
	}
	return out, nil
}

// peerUID returns the uid of the process on the other end of an AF_UNIX
// connection, via SO_PEERCRED.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		ucred   *unix.Ucred
		sockErr error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	return ucred.Uid, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "tsh-touchid-helper: %v\n", err)
	os.Exit(1)
}
