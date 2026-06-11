#!/bin/bash
# docker/splunk/scripts/seed.sh
# Indexes sample auth and attack logs into Splunk

SPLUNK_URL="https://localhost:8089"
SPLUNK_USER="admin"
SPLUNK_PASS="${SPLUNK_PASSWORD:-changeme}"

# Create main index if it doesn't exist
curl -sk -u "$SPLUNK_USER:$SPLUNK_PASS" \
    "$SPLUNK_URL/services/data/indexes" \
    -d "name=main" -o /dev/null || true

# Index the real auth.log
if [ -f /sample-data/auth.log ]; then
    echo "[seed] Indexing auth.log..."
    /opt/splunk/bin/splunk add oneshot /sample-data/auth.log \
        -index main \
        -sourcetype linux_secure \
        -auth "$SPLUNK_USER:$SPLUNK_PASS" \
        -host triagasoar-demo 2>/dev/null || true
fi

# Index the synthetic attack log
if [ -f /sample-data/attack.log ]; then
    echo "[seed] Indexing attack.log (synthetic attack scenarios)..."
    /opt/splunk/bin/splunk add oneshot /sample-data/attack.log \
        -index main \
        -sourcetype linux_secure \
        -auth "$SPLUNK_USER:$SPLUNK_PASS" \
        -host prod-web-01 2>/dev/null || true
fi

echo "[seed] Data seeding complete"

# Verify
COUNT=$(/opt/splunk/bin/splunk search "index=main | stats count" \
    -auth "$SPLUNK_USER:$SPLUNK_PASS" \
    -output_mode json 2>/dev/null | \
    python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('results',[{}])[0].get('count','?'))" 2>/dev/null || echo "?")
echo "[seed] Events in main index: $COUNT"