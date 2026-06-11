#!/bin/bash
# docker/splunk/scripts/setup.sh
# Runs after Splunk is healthy. Configures MCP, creates role, token, seeds data.

set -e

SPLUNK_URL="https://localhost:8089"
SPLUNK_USER="admin"
SPLUNK_PASS="${SPLUNK_PASSWORD:-changeme}"
TOKEN_FILE="/tmp/splunk_mcp_token"

echo "[setup] Waiting for Splunk to be ready..."
until curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" "$SPLUNK_URL/services/server/info" -o /dev/null 2>&1; do
    sleep 5
done
echo "[setup] Splunk is ready"

# ── Create mcp_user role ───────────────────────────────────────────────────────
echo "[setup] Creating mcp_user role..."
curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    "$SPLUNK_URL/services/authorization/roles" \
    -d "name=mcp_user&capabilities=mcp_tool_execute&imported_roles=user" \
    -o /dev/null || true

# ── Create mcp_svc user ────────────────────────────────────────────────────────
echo "[setup] Creating mcp_svc user..."
curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    "$SPLUNK_URL/services/authentication/users" \
    -d "name=mcp_svc&password=mcp_svc_pass_$(openssl rand -hex 8)&roles=mcp_user&roles=admin" \
    -o /dev/null || true

# ── Enable token authentication ────────────────────────────────────────────────
echo "[setup] Enabling token auth..."
curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    "$SPLUNK_URL/services/admin/token-auth/tokens_auth" \
    -d "disabled=false" \
    -o /dev/null || true

# ── Create MCP bearer token ────────────────────────────────────────────────────
echo "[setup] Creating MCP bearer token..."
RESPONSE=$(curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    "$SPLUNK_URL/services/authorization/tokens?output_mode=json" \
    -d "name=mcp_token&audience=mcp&expires_on=+365d")

TOKEN=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
try:
    print(data['entry'][0]['content']['token'])
except:
    print('')
" 2>/dev/null)

if [ -n "$TOKEN" ]; then
    echo "$TOKEN" > "$TOKEN_FILE"
    echo "[setup] MCP token created and saved to $TOKEN_FILE"
else
    echo "[setup] WARNING: Could not create token, trying alternative method..."
    # Fallback: use basic auth token
    TOKEN=$(curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
        "$SPLUNK_URL/services/auth/login?output_mode=json" \
        -d "username=$SPLUNK_USER&password=$SPLUNK_PASS" | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('sessionKey',''))")
    echo "$TOKEN" > "$TOKEN_FILE"
fi

# ── Configure MCP Server app ───────────────────────────────────────────────────
echo "[setup] Configuring MCP Server..."
mkdir -p /opt/splunk/etc/apps/Splunk_MCP_Server/local

# Generate keypair for MCP
openssl genrsa -out /opt/splunk/etc/apps/Splunk_MCP_Server/local/mcp_private.pem 2048 2>/dev/null
openssl rsa -in /opt/splunk/etc/apps/Splunk_MCP_Server/local/mcp_private.pem \
    -pubout -out /opt/splunk/etc/apps/Splunk_MCP_Server/local/mcp_public.pem 2>/dev/null

cat > /opt/splunk/etc/apps/Splunk_MCP_Server/local/mcp.conf << MCPCONF
[mcp]
private_key_path = /opt/splunk/etc/apps/Splunk_MCP_Server/local/mcp_private.pem
public_key_path = /opt/splunk/etc/apps/Splunk_MCP_Server/local/mcp_public.pem
enabled = true
MCPCONF

echo "[setup] MCP Server configured"

# ── Seed sample data ────────────────────────────────────────────────────────────
echo "[setup] Seeding sample data..."
/seed.sh

echo "[setup] Setup complete. Token available at $TOKEN_FILE"