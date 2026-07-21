#!/usr/bin/env bash
# Bootstrap the deployed instance's internal DB:
#   1. build internal.db locally (first admin + provider switches) — see
#      bootstrap_internal_db.py; extra flags (--username, --signups, ...) are
#      passed through to it
#   2. wake the machine (an HTTP request auto-starts it), sftp the file up,
#      swap it into place at /mnt/internal.db, restart the app
#
# Replaces the remote internal DB wholesale — accounts/sessions that only
# exist remotely are lost. Intended for first-boot bootstrap; after that,
# manage accounts through the admin UI or `fly ssh console` + the
# `datasette accounts` CLI on the machine.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

DB="$ROOT/internal.db"

echo "==> Building $DB"
(cd "$ROOT" && uv run python scripts/bootstrap_internal_db.py "$DB" "$@")

echo
echo "==> Uploading to $APP:/mnt/internal.db"
echo "    This REPLACES the remote internal DB (accounts, sessions, settings)."
read -r -p "Continue? [y/N] " reply
[[ "$reply" == [yY]* ]] || { echo "aborted"; exit 1; }

# Wake the machine — auto_start_machines starts it on an HTTP request, and
# ssh/sftp need it running.
curl -s -o /dev/null --max-time 30 "$URL/" || true

# sftp `put` refuses to overwrite, so upload to a scratch name and mv into
# place, clearing any stale WAL/SHM sidecars from the previous DB.
fly ssh console --app "$APP" -C "rm -f /mnt/internal.db.new"
echo "put $DB /mnt/internal.db.new" | fly ssh sftp shell --app "$APP"
fly ssh console --app "$APP" -C \
  "sh -c 'rm -f /mnt/internal.db /mnt/internal.db-wal /mnt/internal.db-shm && mv /mnt/internal.db.new /mnt/internal.db'"

echo "==> Restarting so Datasette reopens the new DB"
fly apps restart "$APP"

echo
echo "Done. Sign in at $URL/-/login"
