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

// Bounded, explicit SEP readiness for the helper daemon's start-up (I1b
// boot-order).
//
// At boot the SEP driver is still bringing up its key store when
// multi-user.target (and with it the helper) starts. An unseal through
// /dev/trusted_unseal during that window is guaranteed to fail: the driver has
// not yet reached the SKS endpoint, so refkey_unseal_trusted has no keybag
// session and the module returns EBADMSG. The previous behaviour relied on
// systemd's Restart=on-failure to paper over the race with one or two failed
// restarts.
//
// The driver exposes a passive diagnostics group
// (Documentation/ABI/testing/sysfs-driver-apple-sep in aurora-linux) whose
// "keystore" attribute reads "open" once that bring-up has registered and
// initialised the key store. Prefer that signal over blind retries: wait for it
// before the first unseal, then retry any remaining transient failure with
// backoff, and fail closed when the deadline passes so the caller never serves
// without its keys.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gravitational/trace"
)

const (
	// sepDiagGlob finds the SEP driver's passive diagnostics group. A kernel
	// without the group leaves the glob empty and the code falls back to
	// retrying the unseal.
	sepDiagGlob = "/sys/bus/platform/devices/*.sep/diag"
	// sepDiagABI is the diag interface version this code understands; see
	// Documentation/ABI/testing/sysfs-driver-apple-sep.
	sepDiagABI = "1"

	// DefaultSEPReadyTimeout bounds the whole start-up wait. The SEP bring-up
	// settles within a few seconds of boot; 60s is generous headroom while
	// still failing closed well before a systemd start timeout (the unit is
	// Type=simple, so there is none) and leaving Restart=on-failure as the
	// outer backstop.
	DefaultSEPReadyTimeout = 60 * time.Second

	// sepReadyWaitNumerator/Denominator cap the signal-only wait at 3/4 of the
	// timeout, so a diag group that is present but never reports "open" still
	// gets at least one real unseal attempt before the deadline.
	sepReadyWaitNumerator   = 3
	sepReadyWaitDenominator = 4
)

// Tunables, as variables so tests can shorten them.
var (
	// sepReadyPollInterval is how often the readiness signal is re-read.
	sepReadyPollInterval = 500 * time.Millisecond
	// sepUnsealBaseBackoff and sepUnsealMaxBackoff bound the backoff between
	// unseal attempts after the key store is open.
	sepUnsealBaseBackoff = 500 * time.Millisecond
	sepUnsealMaxBackoff  = 5 * time.Second
)

// sepDiag is the subset of the driver's diag group used to decide readiness.
type sepDiag struct {
	ABI       string
	Attach    string
	Endpoints string
	Keystore  string
	Keybag    string
}

func (d sepDiag) String() string {
	return fmt.Sprintf("abi=%s attach=%s endpoints=%s keystore=%s keybag=%s",
		d.ABI, d.Attach, d.Endpoints, d.Keystore, d.Keybag)
}

// ready reports whether the driver has opened the key store, which is what the
// ref-key/keybag path behind the unseal device needs. Touch ID activation is a
// separate, later step, so the sensor/touchid attributes are deliberately
// ignored.
func (d sepDiag) ready() bool { return d.Keystore == "open" }

// readSEPDiag is a package variable so tests can substitute a fake. ok is false
// when the kernel does not expose the diag group or a version we understand.
var readSEPDiag = readSEPDiagFromSysfs

func readSEPDiagFromSysfs() (sepDiag, bool) {
	dirs, err := filepath.Glob(sepDiagGlob)
	if err != nil || len(dirs) == 0 {
		return sepDiag{}, false
	}
	for _, dir := range dirs {
		d := sepDiag{
			ABI:       readDiagAttr(dir, "abi"),
			Attach:    readDiagAttr(dir, "attach"),
			Endpoints: readDiagAttr(dir, "endpoints"),
			Keystore:  readDiagAttr(dir, "keystore"),
			Keybag:    readDiagAttr(dir, "keybag"),
		}
		if d.ABI == sepDiagABI {
			return d, true
		}
	}
	return sepDiag{}, false
}

// readDiagAttr reads one attribute of the diag group. A single token followed
// by a newline is the documented shape.
func readDiagAttr(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// preloadAllKeys is a package variable so tests can substitute a fake unseal.
var preloadAllKeys = PreloadAllKeys

// UnsealWithBackoff unseals every credential key before the helper serves.
//
// When the kernel exposes the SEP diag group, it waits for the key store to
// read "open" before the first attempt; otherwise it goes straight to bounded
// retries. Either way a non-nil error means nothing was unsealed and the caller
// must not serve (fail closed).
func UnsealWithBackoff(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = DefaultSEPReadyTimeout
	}
	start := time.Now()
	deadline := start.Add(timeout)

	hasCreds, err := hasSealedCredentials()
	if err != nil {
		return trace.Wrap(err, "check the credential store")
	}
	if !hasCreds {
		logger.InfoContext(context.Background(), "No sealed credentials to unseal")
		return nil
	}

	// The SEP diag group is the preferred readiness signal: while the key store
	// is not open, an unseal is guaranteed to fail with EBADMSG.
	if d, ok := readSEPDiag(); ok && !d.ready() {
		logger.InfoContext(context.Background(), "Waiting for the SEP key store before unsealing",
			"keystore", d.Keystore, "keybag", d.Keybag, "attach", d.Attach, "endpoints", d.Endpoints)
		readyDeadline := start.Add(timeout * sepReadyWaitNumerator / sepReadyWaitDenominator)
		if err := waitForSEPKeyStore(readyDeadline); err != nil {
			logger.WarnContext(context.Background(), "SEP key store did not open; attempting the unseal anyway",
				"error", err)
		} else {
			logger.InfoContext(context.Background(), "SEP key store is open",
				"waited", time.Since(start).Round(time.Millisecond).String())
		}
	}

	attempt := 0
	var lastErr error
	for {
		attempt++
		err := preloadAllKeys()
		if err == nil {
			if attempt > 1 {
				logger.InfoContext(context.Background(), "Unsealed touch ID credential keys after retries",
					"attempts", attempt, "elapsed", time.Since(start).Round(time.Millisecond).String())
			}
			return nil
		}
		lastErr = err
		attrs := []any{
			"attempt", attempt,
			"error", err,
			"elapsed", time.Since(start).Round(time.Millisecond).String(),
		}
		if d, ok := readSEPDiag(); ok {
			attrs = append(attrs, "keystore", d.Keystore, "keybag", d.Keybag, "attach", d.Attach)
		}
		logger.WarnContext(context.Background(), "Failed to unseal the SEP credential store", attrs...)

		if !sleepUntil(deadline, unsealBackoff(attempt)) {
			return trace.Wrap(lastErr, "SEP credential store did not unseal within %s after %d attempt(s)", timeout, attempt)
		}
	}
}

// waitForSEPKeyStore polls the diag group until the key store reads "open" or
// the deadline passes.
func waitForSEPKeyStore(deadline time.Time) error {
	var last sepDiag
	for {
		d, ok := readSEPDiag()
		if ok {
			last = d
			if d.ready() {
				return nil
			}
		}
		if !sleepUntil(deadline, sepReadyPollInterval) {
			if ok {
				return trace.Errorf("key store still %q (%s)", last.Keystore, last)
			}
			return trace.Errorf("SEP diag interface disappeared")
		}
	}
}

// unsealBackoff returns the exponential backoff for the given 1-based attempt,
// capped at sepUnsealMaxBackoff.
func unsealBackoff(attempt int) time.Duration {
	d := sepUnsealBaseBackoff
	for i := 1; i < attempt && d < sepUnsealMaxBackoff; i++ {
		d *= 2
	}
	if d > sepUnsealMaxBackoff {
		d = sepUnsealMaxBackoff
	}
	return d
}

// sleepUntil sleeps for d, shortened so it never overshoots deadline, and
// reports whether time remains before the deadline.
func sleepUntil(deadline time.Time, d time.Duration) bool {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	if d > remaining {
		d = remaining
	}
	time.Sleep(d)
	return time.Now().Before(deadline)
}

// hasSealedCredentials reports whether the store holds at least one sealed
// blob. It counts blobs, not credentials-index entries: a blob is the key
// material the unseal device would have to recover.
func hasSealedCredentials() (bool, error) {
	dir, err := credsDir()
	if err != nil {
		return false, trace.Wrap(err)
	}
	blobs, err := filepath.Glob(filepath.Join(dir, "*.blob"))
	if err != nil {
		return false, trace.Wrap(err)
	}
	return len(blobs) > 0, nil
}
