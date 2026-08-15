#!/usr/bin/env bash
# Publish companion/ into the PUBLIC graffito repo's Pages tree
# (github.com/ByteApps/graffito → docs/companion/ → GitHub Pages at
# https://byteapps.com/graffito/companion/).
#
# Canonical source stays HERE (prime-graffito/companion — its tests and
# the Prime e2e live next to it); never edit graffito/docs/companion
# directly. The old chain-notes-companion deploy-mirror repo is archived
# and serves only redirects (it existed because prime-graffito was
# once private; both repos are public since 2026-07-11, and the companion
# moved under the Graffito product home 2026-08-12).
set -euo pipefail

GRAFFITO="${GRAFFITO_REPO:-$HOME/Projects/prime/graffito}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$GRAFFITO/docs/companion"

[ -d "$GRAFFITO/.git" ] || { echo "graffito checkout not found at $GRAFFITO" >&2; exit 1; }
mkdir -p "$DEST"
cp "$HERE/companion/index.html" "$HERE/companion/viewer.html" \
   "$HERE/companion/note.html" "$HERE/companion/chain-scan.js" \
   "$HERE/companion/owner-probe.js" \
   "$HERE/companion/server.py" \
   "$HERE/companion/jsqr.js" "$HERE/companion/qrcode-gen.js" \
   "$HERE/companion/ur.js" "$DEST/"
cd "$GRAFFITO"
if [ -z "$(git status --porcelain docs/companion)" ]; then
    echo "graffito docs/companion already up to date"
    exit 0
fi
git add docs/companion
git commit -m "Sync companion from prime-chain-notes ($(cd "$HERE" && git rev-parse --short HEAD))"
git push
echo "published — https://byteapps.com/graffito/companion/"
