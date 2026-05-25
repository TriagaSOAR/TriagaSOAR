#!/bin/bash
# Simulates a brute force → successful login → privilege escalation attack chain
# Writes directly to /var/log/auth.log on the Splunk VM

ATTACKER_IP="10.10.10.99"
TARGET_USER="inf"
LOG_FILE="/var/log/auth.log"

echo "[*] Starting attack simulation..."

# Phase 1: Brute force (50 failed attempts)
echo "[*] Phase 1: Brute force attempts from $ATTACKER_IP"
for i in $(seq 1 50); do
  echo "$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+00:00") inf sshd[1337]: Failed password for invalid user admin from $ATTACKER_IP port $(shuf -i 10000-65000 -n 1) ssh2" >> $LOG_FILE
  sleep 0.1
done

# Phase 2: Successful login
echo "[*] Phase 2: Successful login"
echo "$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+00:00") inf sshd[1337]: Accepted password for $TARGET_USER from $ATTACKER_IP port 54321 ssh2" >> $LOG_FILE
echo "$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+00:00") inf sshd[1337]: pam_unix(sshd:session): session opened for user $TARGET_USER(uid=1000) by (uid=0)" >> $LOG_FILE

# Phase 3: Privilege escalation
echo "[*] Phase 3: Privilege escalation"
echo "$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+00:00") inf sudo: $TARGET_USER : TTY=pts/0 ; PWD=/home/$TARGET_USER ; USER=root ; COMMAND=/bin/bash" >> $LOG_FILE
echo "$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+00:00") inf sudo: pam_unix(sudo:session): session opened for user root(uid=0) by $TARGET_USER(uid=1000)" >> $LOG_FILE

# Phase 4: Lateral movement to second user
echo "$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+00:00") inf sudo: inf : TTY=pts/0 ; PWD=/home/inf ; USER=victim ; COMMAND=/bin/bash" >> $LOG_FILE
echo "$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+00:00") inf sudo: pam_unix(sudo:session): session opened for user victim(uid=1001) by inf(uid=1000)" >> $LOG_FILE

echo "[+] Attack simulation complete. Wait ~60s for Splunk to index, then run triage."