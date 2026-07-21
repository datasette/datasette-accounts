#!/usr/bin/env bash
# Push provider credentials from .env to Fly as secrets. Empty vars are
# skipped (an unconfigured provider is inert). Generates DATASETTE_SECRET on
# first run and writes it back to .env so it stays stable across deploys.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

ENV_FILE="$ROOT/.env"
[ -f "$ENV_FILE" ] || { echo "No .env — cp .env.example .env and fill it in" >&2; exit 1; }

set -a
source "$ENV_FILE"
set +a

if [ -z "${DATASETTE_SECRET:-}" ]; then
  DATASETTE_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  # Persist it: a regenerated secret would invalidate cookies + in-flight
  # OAuth state on every future `secrets.sh` run.
  if grep -q '^DATASETTE_SECRET=$' "$ENV_FILE"; then
    sed -i '' "s/^DATASETTE_SECRET=$/DATASETTE_SECRET=$DATASETTE_SECRET/" "$ENV_FILE"
  else
    echo "DATASETTE_SECRET=$DATASETTE_SECRET" >>"$ENV_FILE"
  fi
  echo "Generated DATASETTE_SECRET and saved it to .env"
fi

VARS=(
  DATASETTE_SECRET
  DATASETTE_GITHUB_CLIENT_ID DATASETTE_GITHUB_CLIENT_SECRET
  DATASETTE_DISCORD_CLIENT_ID DATASETTE_DISCORD_CLIENT_SECRET
  DATASETTE_BLUESKY_PUBLIC_URL
)

args=()
for var in "${VARS[@]}"; do
  value="${!var:-}"
  if [ -n "$value" ]; then
    args+=("$var=$value")
  else
    echo "skipping $var (empty)"
  fi
done

[ ${#args[@]} -gt 0 ] || { echo "Nothing to set" >&2; exit 1; }

# --stage: don't trigger a restart per call; values land on the next deploy
# (or immediately if the app isn't deployed yet).
fly secrets set --app "$APP" --stage "${args[@]}"
echo "Staged ${#args[@]} secrets for $APP (applied on next deploy)."
