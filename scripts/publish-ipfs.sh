#!/usr/bin/env bash
# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Publish the Lullwire web app (not the relay) to IPFS with Kubo.
# Usage: ./publish-ipfs.sh https://your-host/lullwire/relay.php
set -euo pipefail

RELAY="${1:?usage: $0 https://your-host/path/relay.php}"
[[ "$RELAY" =~ ^https://[A-Za-z0-9._~:/?=\&%-]+$ ]] || { echo "Relay must be a plain https:// URL" >&2; exit 1; }
command -v ipfs >/dev/null || { echo "Install Kubo first: https://docs.ipfs.tech/install/command-line/" >&2; exit 1; }

SRC="$(cd "$(dirname "$0")/../web" && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

cp "$SRC"/{index.html,style.css,app.js,call.js,worklet.js,sw.js,manifest.json,icon.svg,icon-192.png,icon-512.png,icon-maskable.png,apple-touch-icon.png} "$OUT"/ && cp -r "$SRC/vendor" "$OUT"/
printf 'window.LULLWIRE_CONFIG = { relay: "%s" };\n' "$RELAY" > "$OUT/config.js"
# Sign this copy (config.js changed), so installed apps accept it as an update.
VERSION="$(sed -n 's/^var version = "\(.*\)"/\1/p' "$SRC/../cmd/lullwire-relay/main.go")"
if grep -q "^const RELEASE_KEY = '[A-Za-z0-9_-]\{80,\}';" "$OUT/sw.js"; then
  (cd "$SRC/.." && go run ./cmd/lullwire-release sign "$VERSION" -dir "$OUT" && go run ./cmd/lullwire-release verify -dir "$OUT")
else
  echo "note: no release key pinned in sw.js yet, so this copy is unsigned (see docs/RELEASING.md)" >&2
fi

CID="$(ipfs add -r -Q --cid-version=1 "$OUT")"
echo "CID: $CID"
echo
echo "Test it:  https://$CID.ipfs.dweb.link/"
echo
echo "For a stable address (keeps users' keys across updates), set a DNS TXT record:"
echo "  _dnslink.lullwire.example.com  TXT  \"dnslink=/ipfs/$CID\""
echo "then open https://lullwire-example-com.ipns.dweb.link/ (dots in the domain become dashes)."
echo
echo "Keep this CID online: leave your Kubo node running, or pin it with a pinning service."
