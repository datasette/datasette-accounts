#!/usr/bin/env bash
# Pull build artifacts out of the datasette-accounts checkout:
#   1. build the Svelte frontend (ships inside the wheel as static/gen)
#   2. build the datasette-accounts wheel into wheels/
#   3. flat-copy the three sample providers into plugins/ (each is a loose
#      --plugins-dir module; flat copies need no loader shim)
#   4. refresh uv.lock so `uv sync --locked` in the Docker build matches
set -euo pipefail
source "$(dirname "$0")/lib.sh"

# This project lives at <checkout>/fly, so the checkout is the parent dir.
SRC="${DATASETTE_ACCOUNTS_SRC:-$(cd "$ROOT/.." && pwd)}"
[ -d "$SRC/datasette_accounts" ] || {
  echo "datasette-accounts checkout not found at $SRC (set DATASETTE_ACCOUNTS_SRC)" >&2
  exit 1
}

echo "==> Building frontend in $SRC"
npm run build --prefix "$SRC/frontend"

echo "==> Building wheel"
rm -rf "$ROOT/wheels"
(cd "$SRC" && uv build --wheel --out-dir "$ROOT/wheels")

wheel="$(ls "$ROOT"/wheels/datasette_accounts-*.whl)"
if ! grep -q "$(basename "$wheel")" "$ROOT/pyproject.toml"; then
  echo "Built $(basename "$wheel") but pyproject.toml's [tool.uv.sources] points" >&2
  echo "at a different filename — the version was bumped. Update pyproject.toml." >&2
  exit 1
fi

echo "==> Copying sample providers into plugins/"
rm -rf "$ROOT/plugins"
mkdir -p "$ROOT/plugins"
for sample in discord github bluesky; do
  cp "$SRC/samples/$sample-auth/${sample}_auth.py" "$ROOT/plugins/"
done

echo "==> uv lock"
# --refresh-package: the lock pins the wheel's sha256, and a rebuilt wheel at
# the same path/version is otherwise assumed unchanged (hash mismatch at sync).
(cd "$ROOT" && uv lock --refresh-package datasette-accounts)

echo "OK: $(basename "$wheel") + $(ls "$ROOT/plugins" | tr '\n' ' ')"
