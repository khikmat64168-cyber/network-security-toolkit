#!/usr/bin/env bash
# Put the Networkscan-front build into src/nst/web/static/ so `nst web`
# (and the wheel / Docker image built from this repo) can serve it.
#
#   scripts/fetch_frontend.sh --from ../Networkscan-front
#       Build a local checkout of the frontend repo and copy its dist/.
#
#   scripts/fetch_frontend.sh --release [TAG]
#       Download a published frontend release (default: the tag pinned in
#       ./frontend.version), verify its SHA-256, and unpack it.
#
# Environment:
#   NST_FRONTEND_REPO   owner/name of the frontend repo
#                       (default: khikmat64168-cyber/Networkscan-front)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATIC="$ROOT/src/nst/web/static"
REPO="${NST_FRONTEND_REPO:-khikmat64168-cyber/Networkscan-front}"

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

install_dist() {
  local dist="$1"
  if [[ ! -f "$dist/index.html" ]]; then
    echo "error: $dist does not contain index.html" >&2
    exit 1
  fi
  rm -rf "$STATIC"
  mkdir -p "$STATIC"
  cp -R "$dist"/. "$STATIC"/
  echo "Installed frontend into ${STATIC#"$ROOT"/}"
}

from_checkout() {
  local src="$1"
  if [[ ! -f "$src/package.json" ]]; then
    echo "error: $src is not a Networkscan-front checkout" >&2
    exit 1
  fi
  (cd "$src" && npm ci --no-fund --no-audit && npm run build)
  install_dist "$src/dist"
}

from_release() {
  local tag="${1:-}"
  if [[ -z "$tag" ]]; then
    tag="$(tr -d '[:space:]' < "$ROOT/frontend.version")"
  fi
  if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
    echo "error: '$tag' is not a release tag like v1.0.0" >&2
    exit 1
  fi
  local name="networkscan-front-$tag.tar.gz"
  local base="https://github.com/$REPO/releases/download/$tag"
  # Global, not local: the EXIT trap runs after this function has returned.
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "Downloading $REPO $tag"
  curl -fsSL --retry 3 -o "$tmp/$name" "$base/$name"
  curl -fsSL --retry 3 -o "$tmp/$name.sha256" "$base/$name.sha256"

  local expected actual
  expected="$(awk '{print $1}' "$tmp/$name.sha256")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$name" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$tmp/$name" | awk '{print $1}')"
  fi
  if [[ "$expected" != "$actual" ]]; then
    echo "error: checksum mismatch for $name" >&2
    exit 1
  fi

  mkdir -p "$tmp/dist"
  tar -xzf "$tmp/$name" -C "$tmp/dist"
  install_dist "$tmp/dist"
}

case "${1:-}" in
  --from) [[ $# -eq 2 ]] || usage; from_checkout "$2" ;;
  --release) from_release "${2:-}" ;;
  *) usage ;;
esac
