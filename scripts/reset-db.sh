#!/bin/bash
# Wipes the case database for a clean demo run

DB_PATH="./data/cases.db"

if [ -f "$DB_PATH" ]; then
  rm "$DB_PATH"
  echo "[+] Database wiped: $DB_PATH"
else
  echo "[*] No database found at $DB_PATH, nothing to wipe"
fi

echo "[*] Run 'docker compose up ollama soc-agent' to reinitialize"