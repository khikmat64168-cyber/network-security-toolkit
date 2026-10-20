#!/usr/bin/env bash
# Deploy a release of the NST private console.  Run by GitHub Actions as
# "deploy" after copying this script and docker-compose.yml to the VPS:
#
#   /opt/nst-console/deploy-console.sh v1.2.3
#
# Pulls the image, restarts the console, waits for it to answer on
# loopback and rolls back to the previous tag if it does not.
set -euo pipefail

TAG="${1:?usage: deploy-console.sh <tag>}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || { echo "bad tag: $TAG" >&2; exit 2; }

cd "$(dirname "$0")"
[[ -f .env ]] || { echo "missing $PWD/.env — run console-setup.sh first" >&2; exit 1; }

PREVIOUS="$(sed -n 's/^NST_VERSION=//p' .env)"

set_version() {
  sed -i "s/^NST_VERSION=.*/NST_VERSION=$1/" .env
}

healthy() {
  for _ in $(seq 1 30); do
    curl -fsS --max-time 3 http://127.0.0.1:8765/api/mode >/dev/null 2>&1 && return 0
    sleep 2
  done
  echo "console did not become healthy" >&2
  return 1
}

echo "==> Console $TAG (previous: ${PREVIOUS:-none})"
set_version "$TAG"
if docker compose pull && docker compose up -d --remove-orphans && healthy; then
  docker image prune -f >/dev/null
  echo "==> Console $TAG is running on 127.0.0.1:8765"
  exit 0
fi

echo "==> $TAG failed; rolling back to ${PREVIOUS:-nothing}" >&2
if [[ -n "$PREVIOUS" && "$PREVIOUS" != "$TAG" ]]; then
  set_version "$PREVIOUS"
  docker compose up -d --remove-orphans || true
fi
exit 1
