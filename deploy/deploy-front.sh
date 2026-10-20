#!/usr/bin/env bash
# Activate a Networkscan-front release on the VPS.  Run by the frontend
# repo's GitHub Actions as "deploy", after uploading the release archive
# and its checksum to /srv/networkscan-front/incoming/:
#
#   /opt/nst/deploy/deploy-front.sh v1.2.3
#
# Verifies the SHA-256, unpacks into releases/<tag>, switches the
# "current" symlink atomically (Caddy serves it) and keeps 5 releases.
set -euo pipefail

TAG="${1:?usage: deploy-front.sh <tag>}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || { echo "bad tag: $TAG" >&2; exit 2; }

ROOT=/srv/networkscan-front
ARCHIVE="$ROOT/incoming/networkscan-front-$TAG.tar.gz"
TARGET="$ROOT/releases/$TAG"

[[ -f "$ARCHIVE" && -f "$ARCHIVE.sha256" ]] || { echo "missing $ARCHIVE(.sha256)" >&2; exit 1; }
EXPECTED="$(awk '{print $1}' "$ARCHIVE.sha256")"
ACTUAL="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "checksum mismatch for $ARCHIVE" >&2; exit 1; }

rm -rf "$TARGET.tmp"
mkdir -p "$TARGET.tmp"
tar -xzf "$ARCHIVE" -C "$TARGET.tmp"
[[ -f "$TARGET.tmp/index.html" ]] || { echo "archive has no index.html" >&2; rm -rf "$TARGET.tmp"; exit 1; }
rm -rf "$TARGET"
mv "$TARGET.tmp" "$TARGET"

# Atomic switch: build the new link beside the old one, then rename over it.
ln -sfn "$TARGET" "$ROOT/current.new"
mv -T "$ROOT/current.new" "$ROOT/current"
rm -f "$ARCHIVE" "$ARCHIVE.sha256"

# Keep the five newest releases (and never the active one).
ACTIVE="$(readlink -f "$ROOT/current")"
find "$ROOT/releases" -mindepth 1 -maxdepth 1 -type d -name 'v*' -printf '%T@ %p\n' \
  | sort -rn | tail -n +6 | cut -d' ' -f2- | while read -r old; do
  [[ "$(readlink -f "$old")" == "$ACTIVE" ]] || rm -rf "$old"
done

echo "==> Networkscan-front $TAG is live"
