#!/bin/bash
# docker/splunk/scripts/setup.sh

set -e

SPLUNK_URL="https://localhost:8089"
SPLUNK_USER="admin"
SPLUNK_PASS="${SPLUNK_PASSWORD:-changeme123!}"
TOKEN_FILE="/tmp/splunk_mcp_token"

echo "[setup] Waiting for Splunk to be ready..."
for i in $(seq 1 30); do
    if curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" "$SPLUNK_URL/services/server/info" -o /dev/null 2>&1; then
        echo "[setup] Splunk is ready"
        break
    fi
    sleep 5
done

# ── Create mcp_user role ───────────────────────────────────────────────────────
echo "[setup] Creating mcp_user role..."
curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    "$SPLUNK_URL/services/authorization/roles" \
    -d "name=mcp_user&capabilities=mcp_tool_execute&imported_roles=user" \
    -o /dev/null || true

# ── Enable token authentication ────────────────────────────────────────────────
echo "[setup] Enabling token auth..."
curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    "$SPLUNK_URL/services/admin/token-auth/tokens_auth" \
    -d "disabled=false" \
    -o /dev/null || true

# ── Clean up any ghost credentials ────────────────────────────────────────────
echo "[setup] Cleaning stale MCP credentials..."
python3 -c "
import re, os
meta = '/opt/splunk/etc/apps/Splunk_MCP_Server/metadata/local.meta'
if os.path.exists(meta):
    with open(meta) as f: content = f.read()
    content = re.sub(r'\[passwords/credential%3ASplunk_MCP_Server%3Aprivate_key%3A\][^\[]*', '', content)
    content = re.sub(r'\[passwords/credential%3ASplunk_MCP_Server%3Aprivate_key_previous%3A\][^\[]*', '', content)
    with open(meta, 'w') as f: f.write(content)
" 2>/dev/null || true

rm -f /opt/splunk/etc/apps/Splunk_MCP_Server/local/passwords.conf || true

curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    -X DELETE "$SPLUNK_URL/servicesNS/nobody/Splunk_MCP_Server/storage/passwords/Splunk_MCP_Server%3Aprivate_key%3A" \
    -o /dev/null || true

# ── Restart splunkd to clear in-memory credential cache ───────────────────────
echo "[setup] Restarting splunkd to clear credential cache..."
/opt/splunk/bin/splunk restart --run-as-root 2>/dev/null || true
sleep 20

# Wait for Splunk to come back
for i in $(seq 1 20); do
    if curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" "$SPLUNK_URL/services/server/info" -o /dev/null 2>&1; then
        echo "[setup] Splunk back up"
        break
    fi
    sleep 5
done

# ── Generate encrypted MCP token ──────────────────────────────────────────────
echo "[setup] Generating encrypted MCP token..."
TOKEN=$(curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    "$SPLUNK_URL/services/mcp_token?username=$SPLUNK_USER&expires_on=%2B180d" | \
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('token', ''))
except:
    print('')
" 2>/dev/null)

if [ -z "$TOKEN" ]; then
    echo "[setup] ERROR: Failed to generate MCP token"
    exit 1
fi

printf '%s' "$TOKEN" > "$TOKEN_FILE"
mkdir -p /shared
printf '%s' "$TOKEN" > /shared/splunk_token
echo "[setup] Token saved to /shared/splunk_token"
echo "[setup] Setup complete"