#!/usr/bin/env bash
# Sync artifacts from the datasette-accounts checkout, then build the image
# locally (OrbStack/Docker) and deploy ONE stateful machine. --ha=false is
# load-bearing: the volume attaches to a single machine; two machines would
# get separate, divergent DBs.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

"$ROOT/scripts/sync.sh"

orbstack_docker
cd "$ROOT"
fly deploy --local-only --ha=false "$@"

echo
echo "Deployed: $URL"
