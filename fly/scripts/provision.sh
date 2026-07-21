#!/usr/bin/env bash
# One-time: create the Fly app + its volume WITHOUT deploying, so the public
# URL is known up front — you need it to register the GitHub/Discord OAuth
# callbacks and as DATASETTE_BLUESKY_PUBLIC_URL before the first deploy.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

# FLY_ORG picks the org the app is created in (default: personal).
fly apps create "$APP" ${FLY_ORG:+--org "$FLY_ORG"}
fly volumes create data --app "$APP" --region "$REGION" --size 1 --yes

cat <<EOF

App provisioned (nothing deployed yet). Public URL:

    $URL

Register OAuth callbacks with the providers:
    GitHub:  $URL/-/github-auth/callback
    Discord: $URL/-/discord-auth/callback
    Bluesky: no registration needed — set DATASETTE_BLUESKY_PUBLIC_URL=$URL

Next: cp .env.example .env, fill it in, then scripts/secrets.sh && scripts/deploy.sh
EOF
