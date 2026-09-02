#!/usr/bin/env bash

set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/demo-auth.log" >&2
    exit 2
fi

demo_log=$1
timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
users="root admin deploy backup test service"
process_id=9000
port=41000

for username in $users; do
    printf '%s demo-host sshd[%s]: Failed password for invalid user %s from 203.0.113.50 port %s ssh2\n' \
        "$timestamp" "$process_id" "$username" "$port" >> "$demo_log"
    process_id=$((process_id + 1))
    port=$((port + 1))
done

echo "Appended 6 synthetic SSH login failures to $demo_log."
