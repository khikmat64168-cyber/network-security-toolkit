#!/usr/bin/env bash
# Deploy a backend release on the VPS.  Run by GitHub Actions as "deploy":
#
#   /opt/nst/deploy/deploy.sh v1.2.3
#
# Pulls the image, restarts the services, waits for both backends to
# answer on loopback, and rolls back to the previous tag if they do not.
set -euo pipefail

TAG="${1:?usage: deploy.sh <tag>}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || { echo "bad tag: $TAG" >&2; exit 2; }

cd "$(dirname "$0")"
ENV_FILE=.env
[[ -f $ENV_FILE ]] || { echo "missing $PWD/.env — run vps-setup.sh first" >&2; exit 1; }
[[ -f secrets/console-auth.caddy ]] || { echo "missing console-auth.caddy — run vps-setup.sh first" >&2; exit 1; }

PREVIOUS="$(sed -n 's/^NST_VERSION=//p' "$ENV_FILE")"

set_version() {
  sed -i "s/^NST_VERSION=.*/NST_VERSION=$1/" "$ENV_FILE"
}

healthy() {
  local port
  for port in 8766 8765; do
    for _ in $(seq 1 30); do
      if curl -fsS --max-time 3 "http://127.0.0.1:$port/api/mode" >/dev/null 2>&1; then
        continue 2
      fi
      sleep 2
    done
    echo "backend on port $port did not become healthy" >&2
    return 1
  done
}

echo "==> Deploying $TAG (previous: ${PREVIOUS:-none})"
set_version "$TAG"
if docker compose pull && docker compose up -d --remove-orphans && healthy; then
  docker image prune -f >/dev/null
  echo "==> $TAG is live"
  exit 0
fi

echo "==> $TAG failed; rolling back to ${PREVIOUS:-nothing}" >&2
if [[ -n "$PREVIOUS" && "$PREVIOUS" != "$TAG" ]]; then
  set_version "$PREVIOUS"
  docker compose up -d --remove-orphans || true
fi
exit 1
