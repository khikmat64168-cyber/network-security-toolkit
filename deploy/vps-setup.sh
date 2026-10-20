#!/usr/bin/env bash
# One-time VPS preparation for NST (Ubuntu 22.04 / 24.04).  Run as root:
#
#   sudo bash vps-setup.sh --email you@example.com --ci-key "ssh-ed25519 AAAA... github-actions"
#
# Options:
#   --email ADDRESS     contact for Let's Encrypt (required)
#   --ci-key KEY        public SSH key the GitHub Actions deploy job uses (required)
#   --public-host NAME  public demo host  (default: <ip-with-dashes>.sslip.io)
#   --console-host NAME console host      (default: console.<public-host>)
#   --console-user NAME basic-auth user   (default: admin)
#
# What it does:
#   1. installs Docker (Ubuntu packages), ufw and unattended-upgrades
#   2. creates the unprivileged "deploy" user for CI (docker group, SSH key)
#   3. opens only SSH, 80 and 443 in the firewall
#   4. writes /opt/nst/deploy/.env (with a random console token) and the
#      console basic-auth file (asks for the password)
# It is safe to re-run: existing .env, token and password are kept.
set -euo pipefail

EMAIL="" CI_KEY="" PUBLIC_HOST="" CONSOLE_HOST="" CONSOLE_USER="admin"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --email) EMAIL="$2"; shift 2 ;;
    --ci-key) CI_KEY="$2"; shift 2 ;;
    --public-host) PUBLIC_HOST="$2"; shift 2 ;;
    --console-host) CONSOLE_HOST="$2"; shift 2 ;;
    --console-user) CONSOLE_USER="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
[[ -n "$EMAIL" && -n "$CI_KEY" ]] || { echo "--email and --ci-key are required" >&2; exit 2; }
[[ "$CI_KEY" =~ ^ssh-(ed25519|rsa)\  ]] || { echo "--ci-key must be an ssh-ed25519 or ssh-rsa public key" >&2; exit 2; }

NST_DIR=/opt/nst/deploy
FRONT_DIR=/srv/networkscan-front
CADDY_IMAGE=caddy:2.8.4

echo "==> Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 ufw unattended-upgrades curl openssl >/dev/null
systemctl enable --now docker >/dev/null
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null

echo "==> Deploy user"
if ! id deploy >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash deploy
fi
usermod -aG docker deploy
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
touch /home/deploy/.ssh/authorized_keys
grep -qxF "$CI_KEY" /home/deploy/.ssh/authorized_keys || echo "$CI_KEY" >> /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

echo "==> Directories"
install -d -o deploy -g deploy "$NST_DIR" "$NST_DIR/secrets" "$FRONT_DIR" "$FRONT_DIR/releases" "$FRONT_DIR/incoming"
chmod 700 "$NST_DIR/secrets"

echo "==> Firewall"
ufw allow OpenSSH >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow 443/udp >/dev/null   # HTTP/3
ufw --force enable >/dev/null

echo "==> Host names"
if [[ -z "$PUBLIC_HOST" ]]; then
  IP="$(curl -fsS4 --max-time 10 https://api.ipify.org)"
  [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "could not detect the public IPv4; pass --public-host" >&2; exit 1; }
  PUBLIC_HOST="${IP//./-}.sslip.io"
fi
CONSOLE_HOST="${CONSOLE_HOST:-console.$PUBLIC_HOST}"

ENV_FILE="$NST_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "==> Writing $ENV_FILE"
  umask 077
  cat > "$ENV_FILE" <<EOF
NST_VERSION=v1.0.0
NST_PUBLIC_HOST=$PUBLIC_HOST
NST_CONSOLE_HOST=$CONSOLE_HOST
ACME_EMAIL=$EMAIL
NST_WEB_TOKEN=$(openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-48)
EOF
  chown deploy:deploy "$ENV_FILE"
else
  echo "==> Keeping existing $ENV_FILE"
fi

AUTH_FILE="$NST_DIR/secrets/console-auth.caddy"
if [[ ! -f "$AUTH_FILE" ]]; then
  echo "==> Console password for user '$CONSOLE_USER'"
  read -rsp "Password (min 12 chars): " PW; echo
  read -rsp "Repeat: " PW2; echo
  [[ "$PW" == "$PW2" ]] || { echo "passwords differ" >&2; exit 1; }
  [[ ${#PW} -ge 12 ]] || { echo "password too short" >&2; exit 1; }
  # caddy hash-password only reads a password from a TTY, so pass it via the
  # environment (not argv of a host process) and expand it inside the container.
  # shellcheck disable=SC2016
  HASH="$(PW="$PW" docker run --rm -e PW "$CADDY_IMAGE" sh -c 'caddy hash-password --plaintext "$PW"')"
  [[ "$HASH" == \$2* ]] || { echo "password hashing failed: $HASH" >&2; exit 1; }
  unset PW PW2
  umask 077
  printf 'basic_auth {\n\t%s %s\n}\n' "$CONSOLE_USER" "$HASH" > "$AUTH_FILE"
  chown deploy:deploy "$AUTH_FILE"
else
  echo "==> Keeping existing console password"
fi

cat <<EOF

Done.
  Public demo  : https://$PUBLIC_HOST
  Console      : https://$CONSOLE_HOST   (user: $CONSOLE_USER)
  Console token: sudo grep NST_WEB_TOKEN $ENV_FILE

The first deploy from GitHub Actions copies docker-compose.yml, the
Caddyfile and deploy.sh into $NST_DIR and starts everything.
EOF
