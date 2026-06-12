#!/bin/bash
# docker/velociraptor/setup.sh
# Generates Velociraptor API config for soc-agent to use

VELO_BIN="/velociraptor/velociraptor"
CONFIG="/velociraptor/server.config.yaml"
API_CONFIG="/shared/api.config.yaml"

echo "[velo-setup] Waiting for Velociraptor to start..."
for i in $(seq 1 30); do
    if [ -f "$CONFIG" ]; then
        echo "[velo-setup] Config found"
        break
    fi
    sleep 5
done

if [ ! -f "$CONFIG" ]; then
    echo "[velo-setup] ERROR: Velociraptor config not found"
    exit 1
fi

echo "[velo-setup] Generating API config..."
$VELO_BIN --config "$CONFIG" config api_client \
    --name triagasoar \
    --role administrator \
    "$API_CONFIG" 2>/dev/null

if [ -f "$API_CONFIG" ]; then
    echo "[velo-setup] API config written to $API_CONFIG"
else
    echo "[velo-setup] ERROR: Failed to generate API config"
    exit 1
fi

echo "[velo-setup] Setup complete"