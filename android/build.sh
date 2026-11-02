#!/usr/bin/env bash
# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build the Android app with the plain SDK tools: no Gradle, no libraries.
#   ./android/build.sh            signed release APK  -> android/out/lullwire-relay-<version>.apk
#   ./android/build.sh --debug    debuggable build (remote WebView inspector on)
#
# Needs: JDK 17+, Android SDK build-tools (34+) and one platform (android-35+).
#   ANDROID_HOME   SDK folder            (default ~/Android/Sdk or ~/.local/android-sdk)
#   LULLWIRE_KEYSTORE  release signing key   (default ~/.lullwire-relay/release.jks, or the Hush Relay key
#                      ~/.hush-relay/release.jks if that exists; made on first run)
#   LULLWIRE_KEYPASS   its password          (asked for if not set)
# Keep the keystore safe and backed up: updates must be signed with the same key,
# or Android refuses to install them over the old app.
set -euo pipefail

DEBUG=false; [[ "${1:-}" == "--debug" ]] && DEBUG=true
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
for d in "$SDK" "$HOME/Android/Sdk" "$HOME/.local/android-sdk"; do [[ -n "$d" && -d "$d/build-tools" ]] && { SDK="$d"; break; }; done
[[ -d "$SDK/build-tools" ]] || { echo "Android SDK not found; set ANDROID_HOME" >&2; exit 1; }
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
PLATFORM="$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar"
VERSION="$(sed -n 's/.*android:versionName="\([^"]*\)".*/\1/p' "$HERE/AndroidManifest.xml")"
echo "SDK $(basename "$BT"), $(basename "$(dirname "$PLATFORM")"), version $VERSION"

B="$HERE/build"; OUT="$HERE/out"
rm -rf "$B"; mkdir -p "$B"/{res,gen,classes,assets/www/vendor} "$OUT"

# The app: the same files the relay serves (no service worker needed inside the APK).
cp "$ROOT"/web/{index.html,style.css,app.js,call.js,worklet.js,config.js,manifest.json,icon.svg,icon-192.png} "$B/assets/www/"
cp "$ROOT"/web/vendor/*.js "$ROOT"/web/vendor/*.txt "$B/assets/www/vendor/"
cp "$ROOT"/LICENSE "$B/assets/www/LICENSE.txt"

mkdir -p "$B/gen/dev/altru/lullwire"
cat > "$B/gen/dev/altru/lullwire/BuildConfig.java" <<EOF
package dev.altru.lullwire;
public final class BuildConfig { public static final boolean DEBUG = $DEBUG; }
EOF

# Release builds allow encrypted connections only. Debug builds may also reach a relay
# on the device itself (localhost), for testing.
cp -r "$HERE/res/." "$B/res/"
if $DEBUG; then
  cat > "$B/res/xml/network_security.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">localhost</domain>
        <domain includeSubdomains="false">127.0.0.1</domain>
    </domain-config>
</network-security-config>
XML
fi
"$BT/aapt2" compile --dir "$B/res" -o "$B/res.zip"
DBG=(); $DEBUG && DBG=(--debug-mode)
"$BT/aapt2" link -o "$B/base.apk" -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
  -A "$B/assets" --java "$B/gen" --min-sdk-version 26 --target-sdk-version 35 "${DBG[@]}" "$B/res.zip"

javac -nowarn -Xlint:-options --release 11 -classpath "$PLATFORM" -d "$B/classes" \
  $(find "$HERE/src" "$B/gen" -name '*.java')
"$BT/d8" --min-api 26 --lib "$PLATFORM" $($DEBUG || echo --release) --output "$B" $(find "$B/classes" -name '*.class')
(cd "$B" && zip -qj base.apk classes.dex)
"$BT/zipalign" -f -p 4 "$B/base.apk" "$B/aligned.apk"

if $DEBUG; then
  # Kept between builds so a new debug build installs over the previous one.
  KS="$HOME/.lullwire-relay/debug.jks"; PASS=android
  if [[ ! -f "$KS" ]]; then
    mkdir -p "$(dirname "$KS")"; chmod 700 "$(dirname "$KS")"
    keytool -genkeypair -keystore "$KS" -storepass "$PASS" -keypass "$PASS" -alias debug -keyalg EC -groupname secp256r1 \
      -validity 10000 -dname "CN=Lullwire Relay debug" >/dev/null 2>&1
  fi
  APK="$OUT/lullwire-relay-$VERSION-debug.apk"
else
  KS="${LULLWIRE_KEYSTORE:-$HOME/.lullwire-relay/release.jks}"
  [[ -z "${LULLWIRE_KEYSTORE:-}" && ! -f "$KS" && -f "$HOME/.hush-relay/release.jks" ]] && KS="$HOME/.hush-relay/release.jks"
  PASS="${LULLWIRE_KEYPASS:-${HUSH_KEYPASS:-}}"
  if [[ -z "$PASS" ]]; then read -rsp "Keystore password: " PASS; echo; fi
  export LULLWIRE_KEYPASS="$PASS"   # handed to the tools through the environment, never on the command line
  if [[ ! -f "$KS" ]]; then
    mkdir -p "$(dirname "$KS")"; chmod 700 "$(dirname "$KS")"
    keytool -genkeypair -keystore "$KS" -storepass:env LULLWIRE_KEYPASS -keypass:env LULLWIRE_KEYPASS -alias lullwire -keyalg EC -groupname secp256r1 \
      -validity 10000 -dname "CN=Lullwire Relay" >/dev/null
    chmod 600 "$KS"
    echo "New signing key: $KS  (back it up; future updates need it)"
  fi
  APK="$OUT/lullwire-relay-$VERSION.apk"
fi
if $DEBUG; then export LULLWIRE_KEYPASS="$PASS"; fi
"$BT/apksigner" sign --ks "$KS" --ks-pass env:LULLWIRE_KEYPASS --key-pass env:LULLWIRE_KEYPASS --out "$APK" "$B/aligned.apk"
"$BT/apksigner" verify "$APK"
rm -f "$APK.idsig"
( cd "$OUT" && sha256sum "$(basename "$APK")" > "$(basename "$APK").sha256" )
echo "Built $APK"
echo "Signing certificate SHA-256 (publish this so people can check their download):"
"$BT/apksigner" verify --print-certs "$APK" | sed -n 's/.*SHA-256 digest: //p'
