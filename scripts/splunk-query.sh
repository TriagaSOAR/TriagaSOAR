#!/bin/bash
# Usage: ./scripts/splunk-query.sh 'index=main "10.10.10.99" | head 5'

source .env

QUERY="${1:-index=* | head 5}"

curl -k -X POST https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/mcp \
  -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg q "$QUERY" \
    '{"jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{"name":"splunk_run_query",
    "arguments":{"query":$q,
    "earliest_time":"-1h",
    "latest_time":"now"}}
    }'
  )"