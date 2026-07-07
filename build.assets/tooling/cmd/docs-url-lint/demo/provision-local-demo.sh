#!/usr/bin/env bash
#
# provision-local-demo.sh [demo-dir]
#
# Sets up a local directory for the docs-url-lint MCP demo, using the
# already-authenticated `tsh`/`tctl` session on this machine against the
# live cluster (no beam upload needed - `tctl create` is a client
# operation that talks to the cluster's auth/proxy service directly):
#   1. Grants the editor role permission to manage `app` resources
#      (idempotent - only patches the role if the rule isn't already
#      there).
#   2. Builds a `tctl` binary from this working tree (including the
#      docs-link fix in api/types/app.go's checkMCPStdio) into the demo
#      directory, for this machine's own architecture.
#   3. Writes a deliberately incomplete MCP app resource (missing
#      run_as_host_user) into the demo directory, for an agent there to
#      discover and fix using the docs link in the (patched) error.
#
# Prerequisites:
#   - An active `tsh login` session with permission to edit roles.
#   - The docs-link fix already present in this working tree's
#     api/types/app.go (not yet committed anywhere durable).
#
# Defaults to ~/Desktop/2026-07-mcp-docs-demo if no directory is given.

set -euo pipefail

DEMO_DIR="${1:-$HOME/Desktop/2026-07-mcp-docs-demo}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"

mkdir -p "$DEMO_DIR"

echo "==> Granting editor role permission to manage apps (idempotent)"
TMP_ROLE="$(mktemp)"
trap 'rm -f "$TMP_ROLE" "${TMP_ROLE}.patched"' EXIT
tctl get role/editor --format=json | jq '.[0]' > "$TMP_ROLE"
jq 'if ([.spec.allow.rules[]? | select(.resources == ["app"])] | length) == 0
    then .spec.allow.rules += [{"resources": ["app"], "verbs": ["list", "create", "read", "update", "delete"]}]
    else . end' "$TMP_ROLE" > "${TMP_ROLE}.patched"
tctl create -f "${TMP_ROLE}.patched"

echo "==> Building tctl (with the docs-link fix) into ${DEMO_DIR}"
(cd "$REPO_ROOT" && go build -o "$DEMO_DIR/tctl" ./tool/tctl)

echo "==> Writing the incomplete MCP app config"
cat > "$DEMO_DIR/broken-mcp-app.yaml" << 'YAMLEOF'
kind: app
version: v3
metadata:
  name: demo-mcp-app
spec:
  uri: "mcp+stdio://demo-mcp-app"
  mcp:
    command: "npx"
    args: ["-y", "some-mcp-server"]
YAMLEOF

echo "==> Done. Demo directory: ${DEMO_DIR}"
echo "    Try: cd ${DEMO_DIR} && ./tctl create -f broken-mcp-app.yaml"
