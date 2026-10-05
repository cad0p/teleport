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

// tsh-touchid-helper is the Linux Touch ID helper daemon. It owns the software
// P-256 credentials and performs user presence via fprintd, exposing the same
// JSON-RPC protocol as the macOS helper (PR #64128) over an AF_UNIX socket.
//
// It is meant to run inside the user's active session (so fprintd's polkit
// checks pass) and is reachable only by that user: the socket is 0600 and every
// connection is checked against the configured uid via SO_PEERCRED.
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
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gravitational/teleport/lib/auth/touchid"
)

func main() {
	socketFlag := flag.String("socket", "", "AF_UNIX socket path (default $XDG_RUNTIME_DIR/tsh-touchid.sock)")
	uidFlag := flag.Int("uid", -1, "only accept connections from this uid (default: the current uid)")
	flag.Parse()

	allowedUID := os.Getuid()
	if *uidFlag >= 0 {
		allowedUID = *uidFlag
	}

	socketPath := *socketFlag
	if socketPath == "" {
		p, err := touchid.HelperSocketPath()
		if err != nil {
			fatal(err)
		}
		socketPath = p
	}

	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		fatal(fmt.Errorf("create socket dir: %w", err))
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
	if err := os.Chmod(socketPath, 0600); err != nil {
		fatal(fmt.Errorf("chmod socket: %w", err))
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("tsh-touchid-helper listening on %s (uid %d)", socketPath, allowedUID)

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
		if uid != uint32(allowedUID) {
			log.Printf("rejecting connection from uid %d (allowed uid %d)", uid, allowedUID)
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
