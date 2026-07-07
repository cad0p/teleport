#!/usr/bin/env bash
#
# provision-beam.sh <beam-address> [login]
#
# Sets up a Teleport beam for the docs-url-lint MCP demo:
#   1. Grants the editor role permission to manage `app` resources
#      (idempotent - only patches the role if the rule isn't already there).
#   2. Detects the beam's architecture, cross-compiles a `tctl` binary from
#      this working tree (including the docs-link fix in
#      api/types/app.go's checkMCPStdio) for that architecture, and
#      installs it on the beam.
#   3. Uploads a deliberately incomplete MCP app resource (missing
#      run_as_host_user) to the beam's home directory, for an agent there
#      to discover and fix using the docs link in the (patched) error.
#   4. Checks that the beam can actually reach the linked docs page -
#      if it can't, the demo's discovery step won't work, so this fails
#      loudly rather than silently.
#
# Prerequisites:
#   - An active `tsh login` session with permission to edit roles.
#   - The docs-link fix already present in this working tree's
#     api/types/app.go (not yet committed anywhere durable - see the
#     project notes on how to store this as a real commit/branch instead
#     of relying on local working-tree state).
#
# login defaults to "beams", the non-root user this demo's agent runs as.

set -euo pipefail

BEAM="${1:?usage: provision-beam.sh <beam-address> [login]}"
LOGIN="${2:-beams}"

DOCS_URL="https://goteleport.com/docs/enroll-resources/mcp-access/enrolling-mcp-servers/stdio.md"
REMOTE_APP_CONFIG="broken-mcp-app.yaml"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

echo "==> Granting editor role permission to manage apps (idempotent)"
tctl get role/editor --format=json | jq '.[0]' > "$SCRATCH/editor-role.json"
jq 'if ([.spec.allow.rules[]? | select(.resources == ["app"])] | length) == 0
    then .spec.allow.rules += [{"resources": ["app"], "verbs": ["list", "create", "read", "update", "delete"]}]
    else . end' "$SCRATCH/editor-role.json" > "$SCRATCH/editor-role-patched.json"
tctl create -f "$SCRATCH/editor-role-patched.json"

echo "==> Detecting beam architecture"
BEAM_ARCH="$(tsh ssh "${LOGIN}@${BEAM}" -- uname -m)"
case "$BEAM_ARCH" in
  aarch64) GOARCH=arm64 ;;
  x86_64) GOARCH=amd64 ;;
  *)
    echo "error: unrecognized beam architecture: $BEAM_ARCH" >&2
    exit 1
    ;;
esac
echo "    beam is linux/${GOARCH}"

echo "==> Cross-compiling tctl (with the docs-link fix) for linux/${GOARCH}"
(cd "$REPO_ROOT" && GOOS=linux GOARCH="$GOARCH" go build -o "$SCRATCH/tctl" ./tool/tctl)

echo "==> Installing tctl on the beam"
tsh scp "$SCRATCH/tctl" "${LOGIN}@${BEAM}:/tmp/tctl"
tsh ssh "${LOGIN}@${BEAM}" -- 'sudo mv /tmp/tctl /usr/local/bin/tctl && sudo chmod +x /usr/local/bin/tctl'

echo "==> Uploading the incomplete MCP app config"
cat > "$SCRATCH/${REMOTE_APP_CONFIG}" << YAMLEOF
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
tsh scp "$SCRATCH/${REMOTE_APP_CONFIG}" "${LOGIN}@${BEAM}:~/${REMOTE_APP_CONFIG}"

echo "==> Verifying the beam can reach the linked docs page"
STATUS="$(tsh ssh "${LOGIN}@${BEAM}" -- curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$DOCS_URL" || echo "000")"
if [ "$STATUS" != "200" ]; then
  echo "error: beam could not reach ${DOCS_URL} (status ${STATUS}). The demo's discovery step will not work from here." >&2
  exit 1
fi

echo "==> Done. On the beam (as ${LOGIN}), run:"
echo "      tctl create -f ~/${REMOTE_APP_CONFIG}"
