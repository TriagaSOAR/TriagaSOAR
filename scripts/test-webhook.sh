#!/bin/bash
# Test the webhook endpoint with a simulated Splunk alert payload

source .env

curl -s -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "search_name": "Brute Force Detection",
    "sid": "scheduler__admin__search__test123",
    "result": {
      "_raw": "2026-05-27T10:00:00+00:00 inf sshd[1337]: Failed password for invalid user admin from 10.10.10.99 port 54321 ssh2",
      "host": "inf",
      "source": "/var/log/auth.log",
      "sourcetype": "linux_secure"
    },
    "results_link": "http://192.168.122.10:8000/results",
    "owner": "admin",
    "app": "search"
  }' | jq .