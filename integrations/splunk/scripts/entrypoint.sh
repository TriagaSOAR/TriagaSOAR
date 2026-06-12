#!/bin/bash
# docker/splunk/scripts/entrypoint.sh

SETUP_FLAG="/opt/splunk/var/.triagasoar_setup_done"
SPLUNK_USER="admin"
SPLUNK_PASS="${SPLUNK_PASSWORD:-changeme123!}"

# Start Splunk via official entrypoint — this blocks until Splunk is running
/sbin/entrypoint.sh start-service &
SPLUNK_PID=$!

# Wait for splunkd to actually be listening
echo "[entrypoint] Waiting for splunkd to start..."
for i in $(seq 1 60); do
    if curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
        "https://localhost:8089/services/server/info" -o /dev/null 2>/dev/null; then
        echo "[entrypoint] Splunk is up after ${i} attempts"
        break
    fi
    sleep 5
done

# Run one-time setup
if [ ! -f "$SETUP_FLAG" ]; then
    echo "[entrypoint] Running first-boot setup..."
    /setup.sh && touch "$SETUP_FLAG"
    # Copy token to shared volume
    if [ -f /tmp/splunk_mcp_token ]; then
        cp /tmp/splunk_mcp_token /shared/splunk_token
        echo "[entrypoint] Token written to /shared/splunk_token"
    fi
else
    echo "[entrypoint] Setup already done"
    # Re-copy token on restart in case shared volume was reset
    if [ -f /tmp/splunk_mcp_token ]; then
        cp /tmp/splunk_mcp_token /shared/splunk_token
    fi
fi

# Keep container alive
wait $SPLUNK_PID