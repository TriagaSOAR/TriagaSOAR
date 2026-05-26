#!/bin/bash
source .env

echo "[*] Running attack simulation on Splunk VM..."
ssh -t inf@192.168.122.10 "sudo bash ~/attack-simulation.sh"

echo "[*] Waiting 60s for Splunk to index..."
sleep 60

echo "[*] Triggering investigation..."
RESULT=$(curl -s -X POST http://localhost:8000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Brute force + privilege escalation",
    "search_terms": "10.10.10.99",
    "earliest": "-15m",
    "latest": "now",
    "index": "main"
  }')

echo "$RESULT" | jq .report_id 2>/dev/null || echo "Error: $RESULT"

echo "[+] Demo complete."