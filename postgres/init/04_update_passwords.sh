#!/bin/bash
# 04_update_passwords.sh
# Runs after SQL init scripts — updates role passwords from environment variables

set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    ALTER ROLE auth_app WITH PASSWORD '${AUTH_APP_PASSWORD}';
    ALTER ROLE audit_writer WITH PASSWORD '${AUDIT_WRITER_PASSWORD}';
    ALTER ROLE audit_reader WITH PASSWORD '${AUDIT_READER_PASSWORD}';
    SELECT 'Passwords updated' AS status;
EOSQL