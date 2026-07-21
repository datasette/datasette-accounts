# Shared helpers, sourced by the other scripts. Not executable on its own.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$(awk -F"'" '/^app =/{print $2}' "$ROOT/fly.toml")"
REGION="$(awk -F"'" '/^primary_region =/{print $2}' "$ROOT/fly.toml")"
URL="https://$APP.fly.dev"

# flyctl builds locally through Docker but only honors DOCKER_HOST (it ignores
# Docker CLI contexts). Point it at OrbStack's socket when present.
orbstack_docker() {
  local sock="$HOME/.orbstack/run/docker.sock"
  if [ -S "$sock" ] && [ -z "${DOCKER_HOST:-}" ]; then
    export DOCKER_HOST="unix://$sock"
  fi
}
