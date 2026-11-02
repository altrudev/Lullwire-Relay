#!/usr/bin/env bash
# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Android device test on an emulator (or phone) with the WebView shell installed:
#   SERIAL=emulator-5554 ./tests/android/run.sh
# Builds a debug APK and the Go relay, runs the relay on this machine, reaches it from
# the device through adb reverse, and drives both sides over WebView DevTools.
# Needs: Android SDK (adb, build tools), JDK 17+, Go, Node 22+.
set -euo pipefail
cd "$(dirname "$0")/../.."
SDK="${ANDROID_HOME:-$HOME/.local/android-sdk}"; ADB="$SDK/platform-tools/adb"
S=(-s "${SERIAL:?set SERIAL to the device, e.g. emulator-5554}")
PORT=8099; TMP="$(mktemp -d)"
./android/build.sh --debug | grep Built
go build -o "$TMP/relay" ./cmd/lullwire-relay
"$TMP/relay" -addr "127.0.0.1:$PORT" -data "$TMP/data" & RELAY_PID=$!
trap 'kill $RELAY_PID 2>/dev/null; rm -rf "$TMP"' EXIT
# A build signed with a different key can't update the installed app: replace it.
"$ADB" "${S[@]}" install -r -g android/out/lullwire-relay-*-debug.apk >/dev/null 2>&1 || {
  "$ADB" "${S[@]}" uninstall dev.altru.lullwire >/dev/null; "$ADB" "${S[@]}" install -g android/out/lullwire-relay-*-debug.apk >/dev/null; }
"$ADB" "${S[@]}" reverse tcp:$PORT tcp:$PORT >/dev/null
# Two resizable windows, so both apps stay in the foreground (camera and microphone).
"$ADB" "${S[@]}" shell settings put global enable_freeform_support 1
"$ADB" "${S[@]}" shell settings put global force_resizable_activities 1
for p in dev.altru.lullwire org.chromium.webview_shell; do
  "$ADB" "${S[@]}" shell pm clear $p >/dev/null
  "$ADB" "${S[@]}" shell pm grant $p android.permission.CAMERA
  "$ADB" "${S[@]}" shell pm grant $p android.permission.RECORD_AUDIO
  [ $p = dev.altru.lullwire ] && { "$ADB" "${S[@]}" shell pm grant $p android.permission.POST_NOTIFICATIONS 2>/dev/null || true; }
done
"$ADB" "${S[@]}" shell am start --windowingMode 5 -n org.chromium.webview_shell/.WebViewBrowserActivity -d "http://localhost:$PORT/" >/dev/null
sleep 3
"$ADB" "${S[@]}" shell am start --windowingMode 5 -n dev.altru.lullwire/.MainActivity >/dev/null
sleep 4
"$ADB" "${S[@]}" forward tcp:9333 "localabstract:webview_devtools_remote_$("$ADB" "${S[@]}" shell pidof dev.altru.lullwire)" >/dev/null
"$ADB" "${S[@]}" forward tcp:9334 "localabstract:webview_devtools_remote_$("$ADB" "${S[@]}" shell pidof org.chromium.webview_shell)" >/dev/null
ADB="$ADB" SERIAL="$SERIAL" RELAY="http://localhost:$PORT/relay" node tests/android/device.js
