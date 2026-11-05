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

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
)

// TestClusterDefaultSessionTTL covers the read of the cluster default session
// TTL that a login without --ttl requests. Proxies that predate the server fix
// omit the field from /webapi/ping/<connector>, which a client pings whenever
// an auth connector is set (a passwordless profile stores one), so the client
// must read it from the connector-less /webapi/ping.
func TestClusterDefaultSessionTTL(t *testing.T) {
	const clusterTTL = 168 * time.Hour

	newProxy := func(t *testing.T, status int) (addr string, paths func() []string) {
		var mu sync.Mutex
		var seen []string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.URL.Path)
			mu.Unlock()
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			pr := webclient.PingResponse{
				Auth: webclient.AuthenticationSettings{Type: constants.Local},
			}
			if r.URL.Path == "/webapi/ping" {
				pr.Auth.DefaultSessionTTL = types.Duration(clusterTTL)
			}
			w.Header().Set("Content-Type", "application/json")
			assert.NoError(t, json.NewEncoder(w).Encode(pr))
		}))
		t.Cleanup(srv.Close)
		return strings.TrimPrefix(srv.URL, "https://"), func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), seen...)
		}
	}

	newClient := func(addr, connector string) *TeleportClient {
		return &TeleportClient{Config: Config{
			WebProxyAddr:       addr,
			InsecureSkipVerify: true,
			AuthConnector:      connector,
		}}
	}

	t.Run("ping already carries the default", func(t *testing.T) {
		addr, paths := newProxy(t, http.StatusOK)
		pr := &webclient.PingResponse{Auth: webclient.AuthenticationSettings{DefaultSessionTTL: types.Duration(time.Hour)}}
		got := newClient(addr, constants.PasswordlessConnector).ClusterDefaultSessionTTL(context.Background(), pr)
		require.Equal(t, time.Hour, got)
		require.Empty(t, paths(), "no extra ping when the response already has the default")
	})

	t.Run("no connector means the plain ping was used", func(t *testing.T) {
		addr, paths := newProxy(t, http.StatusOK)
		got := newClient(addr, "").ClusterDefaultSessionTTL(context.Background(), &webclient.PingResponse{})
		require.Zero(t, got)
		require.Empty(t, paths(), "no extra ping when the plain ping already answered")
	})

	for _, connector := range []string{constants.PasswordlessConnector, constants.LocalConnector} {
		t.Run("connector "+connector+" falls back to the plain ping", func(t *testing.T) {
			addr, paths := newProxy(t, http.StatusOK)
			got := newClient(addr, connector).ClusterDefaultSessionTTL(context.Background(), &webclient.PingResponse{})
			require.Equal(t, clusterTTL, got)
			require.Equal(t, []string{"/webapi/ping"}, paths())
		})
	}

	t.Run("resolveKeyTTL keeps an explicit --ttl and makes no request", func(t *testing.T) {
		addr, paths := newProxy(t, http.StatusOK)
		tc := newClient(addr, constants.PasswordlessConnector)
		tc.KeyTTL = 30 * time.Minute
		require.Equal(t, 30*time.Minute, tc.resolveKeyTTL(context.Background(), &webclient.PingResponse{}))
		require.Empty(t, paths())
	})

	t.Run("resolveKeyTTL uses the cluster default, else 12h", func(t *testing.T) {
		addr, _ := newProxy(t, http.StatusOK)
		require.Equal(t, clusterTTL, newClient(addr, constants.PasswordlessConnector).resolveKeyTTL(context.Background(), &webclient.PingResponse{}))
		failing, _ := newProxy(t, http.StatusInternalServerError)
		require.Equal(t, apidefaults.CertDuration, newClient(failing, constants.PasswordlessConnector).resolveKeyTTL(context.Background(), &webclient.PingResponse{}))
	})

	t.Run("a negative default is treated as absent", func(t *testing.T) {
		addr, paths := newProxy(t, http.StatusOK)
		pr := &webclient.PingResponse{Auth: webclient.AuthenticationSettings{DefaultSessionTTL: types.Duration(-time.Hour)}}
		require.Zero(t, newClient(addr, "").ClusterDefaultSessionTTL(context.Background(), pr))
		got := newClient(addr, constants.PasswordlessConnector).ClusterDefaultSessionTTL(context.Background(), pr)
		require.Equal(t, clusterTTL, got, "a connector client falls back to the plain ping")
		require.Equal(t, []string{"/webapi/ping"}, paths())
	})

	t.Run("a failed plain ping yields zero, not an error", func(t *testing.T) {
		addr, paths := newProxy(t, http.StatusInternalServerError)
		got := newClient(addr, constants.PasswordlessConnector).ClusterDefaultSessionTTL(context.Background(), &webclient.PingResponse{})
		require.Zero(t, got)
		require.NotEmpty(t, paths())
	})
}
