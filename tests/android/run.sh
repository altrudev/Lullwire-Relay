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
# Wait (up to 60 s) until an app's WebView has opened its DevTools socket, then forward a port to it.
# Fixed sleeps were too short on a busy emulator: the app had no process yet, so the forward went nowhere.
devtools() {
  local pid=""
  for _ in $(seq 60); do
    # (set -e/pipefail: no process yet is not an error here; grep reads everything so the pipe can't break early)
    pid="$("$ADB" "${S[@]}" shell pidof "$1" | tr -d '\r' || true)"
    [ -n "$pid" ] && "$ADB" "${S[@]}" shell cat /proc/net/unix | grep -E "webview_devtools_remote_${pid}[[:space:]]*$" >/dev/null && break
    pid=""; sleep 1
  done
  [ -n "$pid" ] || { echo "FAILED $1 did not start a WebView within 60 s"; exit 1; }
  "$ADB" "${S[@]}" forward "tcp:$2" "localabstract:webview_devtools_remote_$pid" >/dev/null
}
"$ADB" "${S[@]}" shell am start --windowingMode 5 -n org.chromium.webview_shell/.WebViewBrowserActivity -d "http://localhost:$PORT/" >/dev/null
devtools org.chromium.webview_shell 9334
"$ADB" "${S[@]}" shell am start --windowingMode 5 -n dev.altru.lullwire/.MainActivity >/dev/null
devtools dev.altru.lullwire 9333
ADB="$ADB" SERIAL="$SERIAL" RELAY="http://localhost:$PORT/relay" node tests/android/device.js
