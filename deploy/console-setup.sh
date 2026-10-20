#!/usr/bin/env bash
# One-time VPS preparation for the NST private console.  Run as root on a
# host that already has Docker (e.g. a Coolify server):
#
#   sudo bash console-setup.sh --ci-key "ssh-ed25519 AAAA... github-actions-deploy"
#
# It deliberately leaves Docker, the firewall and every existing container
# (Coolify, Traefik, other apps) alone.  It only:
#   1. creates the "deploy" user GitHub Actions logs in as (docker group,
#      the given SSH public key)
#   2. creates /opt/nst-console with a .env holding a random console token
# Safe to re-run: an existing .env and token are kept.
set -euo pipefail

CI_KEY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci-key) CI_KEY="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
[[ "$CI_KEY" =~ ^ssh-(ed25519|rsa)\  ]] || { echo "--ci-key must be an ssh-ed25519 or ssh-rsa public key" >&2; exit 2; }
command -v docker >/dev/null || { echo "Docker is not installed on this host" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "the docker compose plugin is missing" >&2; exit 1; }

DIR=/opt/nst-console

echo "==> deploy user"
if ! id deploy >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash deploy
fi
usermod -aG docker deploy
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
touch /home/deploy/.ssh/authorized_keys
grep -qxF "$CI_KEY" /home/deploy/.ssh/authorized_keys || echo "$CI_KEY" >> /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

echo "==> $DIR"
install -d -m 750 -o deploy -g deploy "$DIR"
if [[ ! -f "$DIR/.env" ]]; then
  umask 077
  cat > "$DIR/.env" <<EOF
NST_VERSION=v1.0.0
NST_WEB_TOKEN=$(openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-48)
EOF
  chown deploy:deploy "$DIR/.env"
  echo "    wrote $DIR/.env with a new console token"
else
  echo "    keeping existing $DIR/.env"
fi

cat <<EOF

Done.  The backend's release workflow copies docker-compose.yml and
deploy-console.sh into $DIR and starts the console.

Open it through an SSH tunnel:
  ssh -L 8765:127.0.0.1:8765 deploy@<this server>
  http://127.0.0.1:8765/
Token: sudo grep NST_WEB_TOKEN $DIR/.env
EOF
