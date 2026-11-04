#!/usr/bin/env bash
# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run the full test suite against a throwaway relay.
#   ./tests/run.sh               # PHP relay: core tests (needs php + node 20+)
#   ./tests/run.sh --go          # Go relay instead (needs go 1.22+)
#   ./tests/run.sh --php-file    # the single-file edition (needs php + go), uploaded to a
#                                # mock hosting account the way a user would
#   add --e2e for the multi-browser test (needs python3 + playwright + chromium)
set -euo pipefail
cd "$(dirname "$0")/.."

IMPL=php; E2E=0
for arg in "$@"; do case "$arg" in --go) IMPL=go;; --php-file) IMPL=phpfile;; --e2e) E2E=1;; esac; done
PORT="${PORT:-8099}"
TMP="$(mktemp -d)"
export LULLWIRE_DATA="$TMP/data"
# Where the app and the relay answer. The single file serves both below its own name.
APP="http://localhost:$PORT/"; RURL="http://localhost:$PORT/relay.php"
if [ "$IMPL" = phpfile ]; then
  echo "== single-file edition"
  # A hosting account: the home folder, with the public web folder inside it.
  mkdir -p "$TMP/home/public_html"
  go run ./cmd/lullwire-release php -out "$TMP/dist" | sed 's/^/  /'
  cp "$TMP/dist/lullwire-relay.php" "$TMP/home/public_html/lullwire-relay.php"
  php -l "$TMP/home/public_html/lullwire-relay.php" >/dev/null && echo "  ok   php -l"
  # No settings at all, as on a fresh upload: the file must choose a safe data folder itself.
  unset LULLWIRE_DATA
  export PHP_CLI_SERVER_WORKERS=16
  php -S "localhost:$PORT" -t "$TMP/home/public_html" >"$TMP/server.log" 2>&1 &
  APP="http://localhost:$PORT/lullwire-relay.php/"; RURL="${APP}relay.php"
elif [ "$IMPL" = go ]; then
  echo "== go build, vet, unit tests"
  test -z "$(gofmt -l cmd web)" && echo "  ok   gofmt" || { echo "  FAIL gofmt: $(gofmt -l cmd web)"; exit 1; }
  go vet ./... && echo "  ok   go vet"
  go test ./... 2>&1 | sed 's/^/  /'
  go build -o "$TMP/lullwire-relay" ./cmd/lullwire-relay && echo "  ok   build"
  "$TMP/lullwire-relay" -addr "localhost:$PORT" -data "$LULLWIRE_DATA" >"$TMP/server.log" 2>&1 &
else
  export PHP_CLI_SERVER_WORKERS=16
  php -S "localhost:$PORT" -t web scripts/router.php >"$TMP/server.log" 2>&1 &
fi
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$TMP"' EXIT
for _ in $(seq 50); do curl -s -o /dev/null "${APP}index.html" && break; sleep 0.1; done

echo "== syntax"
{ command -v php >/dev/null && php -l web/relay.php >/dev/null && echo "  ok   relay.php"; } || [ "$IMPL" = go ]
node --check web/app.js && echo "  ok   app.js"
bash -n scripts/*.sh && echo "  ok   shell scripts"

echo "== core"
RELAY="$RURL" node tests/core.test.js
echo "== compatibility with Hush Relay 0.5"
node tests/compat.test.js

echo "== server hardening"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$RURL?a=put&box=0123456789abcdef0123456789abcdef" --data-binary @web/icon.svg)
[ "$code" = 200 ] && echo "  ok   relay accepts mail" || { echo "  FAIL relay put ($code)"; exit 1; }
if [ "$IMPL" = phpfile ]; then
  # Mail goes above the public web folder, never inside it.
  [ -d "$TMP/home/lullwire-relay-data" ] && [ -z "$(ls -A "$TMP/home/public_html" | grep -vx lullwire-relay.php || true)" ] \
    && echo "  ok   data kept outside the public web folder" || { echo "  FAIL data location: $(ls -A "$TMP/home" "$TMP/home/public_html")"; exit 1; }
  # Only the app's own files are served; everything is byte-for-byte the signed web/ copy.
  for f in index.html app.js sw.js release.json vendor/words.js icon-512.png; do
    curl -s "$APP$f" | cmp -s - "web/$f" || { echo "  FAIL $f differs from web/"; exit 1; }
  done
  curl -s "$APP" | cmp -s - web/index.html && echo "  ok   app files identical to web/ (signed release still matches)" || { echo "  FAIL / is not index.html"; exit 1; }
  for p in relay.config.php lullwire-relay-data/x data/x .htaccess embed.go missing.js; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$APP$p")
    [ "$code" = 404 ] || { echo "  FAIL $p returned $code"; exit 1; }
  done
  echo "  ok   nothing else is served"
  loc=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "http://localhost:$PORT/lullwire-relay.php")
  [ "$loc" = "301 ${APP}" ] && echo "  ok   the bare file name redirects to the app" || { echo "  FAIL redirect: $loc"; exit 1; }
  tag=$(curl -s -D - -o /dev/null "${APP}app.js" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: $tag" "${APP}app.js")" = 304 ] && echo "  ok   unchanged files answer 304" || { echo "  FAIL no 304 for $tag"; exit 1; }
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "${APP}index.html")" = 405 ] && [ "$(curl -s -o /dev/null -w '%{http_code}' "$RURL")" = 405 ] \
    && echo "  ok   wrong methods refused" || { echo "  FAIL methods"; exit 1; }
else
for p in data/ data/recover/ .htaccess scripts/router.php embed.go; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/$p")
  [ "$code" = 404 ] && echo "  ok   /$p not served" || { echo "  FAIL /$p returned $code"; exit 1; }
done
[ -z "$(ls -A web | grep -x data || true)" ] && echo "  ok   no data written inside web/" || { echo "  FAIL data inside web/"; exit 1; }
fi
curl -s -D - -o /dev/null "${APP}index.html" | grep -qi "frame-ancestors 'none'" && echo "  ok   pages refuse to be framed" || { echo "  FAIL no frame-ancestors header"; exit 1; }
# New recovery slots are rate limited per client (5 per day).
codes=""
for i in 1 2 3 4 5 6 7; do
  l=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n'); t=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  codes="$codes $(curl -s -o /dev/null -w '%{http_code}' -X POST "$RURL?a=rput" -d "{\"l\":\"$l\",\"t\":\"$t\",\"d\":\"abc\"}")"
done
echo "$codes" | grep -q 429 && echo "  ok   new recovery slots rate limited ($codes )" || { echo "  FAIL slot rate limit ($codes )"; exit 1; }
# Behind a proxy, limits apply per real client: the 7th+ live connection from one client gets 429,
# while another client behind the same proxy is unaffected.
live() { curl -s -o /dev/null -w '%{http_code} ' -H "X-Forwarded-For: $1" -X POST "$RURL?a=get&wait=4" -d "{\"s\":\"$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')\"}"; }
burst=$( (for i in 1 2 3 4 5 6 7 8; do live 198.51.100.7 & done; wait) )
sleep 0.3; otherip=$(live 203.0.113.9)
echo "$burst" | grep -q 429 && [ "$otherip" = "200 " ] && echo "  ok   live connections capped per client behind a proxy ($burst| other client: $otherip)" || { echo "  FAIL per-client live cap ($burst| other: $otherip)"; exit 1; }
if [ "$IMPL" = go ]; then
  # A data folder inside a served folder must be refused at startup.
  if "$TMP/lullwire-relay" -addr "localhost:$((PORT+1))" -web web -data web/data >"$TMP/refuse.log" 2>&1; then echo "  FAIL started with data inside web/"; exit 1; fi
  grep -q "inside the served folder" "$TMP/refuse.log" && [ ! -d web/data ] && echo "  ok   relay refuses to run with an exposed data folder" || { echo "  FAIL: $(cat "$TMP/refuse.log")"; exit 1; }
  # Graceful shutdown: a waiting long-poll is answered with [] and the process exits cleanly.
  "$TMP/lullwire-relay" -addr "localhost:$((PORT+2))" -data "$TMP/data2" >"$TMP/stop.log" 2>&1 &
  SPID=$!; sleep 0.5
  sec=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  sbox=$(printf '%s' "$sec" | sha256sum | cut -c1-32)
  curl -s -o /dev/null -X POST "http://localhost:$((PORT+2))/relay.php?a=put&box=$sbox" --data-binary @web/icon.svg
  ids=$(curl -s -X POST "http://localhost:$((PORT+2))/relay.php?a=get" -d "{\"s\":\"$sec\"}" | grep -o '"id":"[0-9a-f]*"' | cut -d'"' -f4)
  curl -s -o /dev/null -X POST "http://localhost:$((PORT+2))/relay.php?a=ack" -d "{\"s\":\"$sec\",\"ids\":[\"$ids\"]}"
  ( curl -s -X POST "http://localhost:$((PORT+2))/relay.php?a=get&wait=15" -d "{\"s\":\"$sec\"}" > "$TMP/lp.out"; echo "rc=$?" >> "$TMP/lp.out" ) &
  LP=$!; sleep 0.6; kill -TERM $SPID; wait $LP; wait $SPID; rc=$?
  grep -q '^\[\]' "$TMP/lp.out" && grep -q 'rc=0' "$TMP/lp.out" && [ $rc = 0 ] && echo "  ok   graceful shutdown answers waiting long-polls" || { echo "  FAIL shutdown: $(cat "$TMP/lp.out") exit=$rc"; exit 1; }
  for p in relay.php embed.go .htaccess; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/$p")
    [ "$code" = 405 ] || [ "$code" = 404 ] && echo "  ok   GET /$p gives $code" || { echo "  FAIL /$p returned $code"; exit 1; }
  done
else
# Requests that really come from outside cannot spoof X-Forwarded-For (only loopback proxies are trusted).
grep -q "preg_match('/^(127" web/relay.php && echo "  ok   forwarded addresses trusted only from local proxies" || { echo "  FAIL proxy trust check missing"; exit 1; }
# Without the router or LULLWIRE_DATA, php -S must refuse rather than expose web/data.
env -u LULLWIRE_DATA php -S "localhost:$((PORT+1))" -t web >/dev/null 2>&1 &
PID2=$!
sleep 0.5
body=$(curl -s -X POST "http://localhost:$((PORT+1))/relay.php?a=get" -d '{}')
kill $PID2 2>/dev/null
echo "$body" | grep -q "LULLWIRE_DATA" && [ ! -d web/data ] && echo "  ok   relay refuses to run with an exposed data folder" || { echo "  FAIL exposed data folder not refused: $body"; rm -rf web/data; exit 1; }
fi

if [ "$E2E" = 1 ]; then
  echo "== browsers"
  # The earlier stages used up this client's rate limits; start from a clean slate.
  # The Go relay runs the realistic setup: a private path and an invite-only relay.
  BASE="${APP}index.html"; JOIN=""
  if [ "$IMPL" = go ]; then
    kill $PID 2>/dev/null; wait $PID 2>/dev/null || true
    JOIN="e2e-join-code"
    "$TMP/lullwire-relay" -addr "localhost:$PORT" -data "$TMP/e2e-data" -path /e2e-private/ -join-code "$JOIN" >>"$TMP/server.log" 2>&1 &
    PID=$!
    BASE="http://localhost:$PORT/e2e-private/index.html"
    for _ in $(seq 50); do curl -s -o /dev/null "$BASE" && break; sleep 0.1; done
    [ "$(curl -s "http://localhost:$PORT/")" != "$(curl -s "$BASE")" ] && echo "  ok   front page differs from the private app" || { echo "  FAIL front page shows the app"; exit 1; }
  else
    rm -rf "${LULLWIRE_DATA:-$TMP/home/lullwire-relay-data}/limits"
  fi
  LOGAT=$(wc -l < "$TMP/server.log")
  BASE="$BASE" JOIN="$JOIN" python3 tests/e2e.py
  if [ "$IMPL" = phpfile ]; then
    # Without a router script, PHP's server logs every request line, like a host's access
    # log: the app's deliveries must not put anyone's mailbox in it.
    sent=$(tail -n +"$((LOGAT + 1))" "$TMP/server.log" | grep -c 'a=send' || true)
    leaked=$(tail -n +"$((LOGAT + 1))" "$TMP/server.log" | grep -c 'box=' || true)
    [ "$sent" -gt 0 ] && [ "$leaked" = 0 ] && echo "  ok   access log: $sent deliveries, no mailbox in any request line" \
      || { echo "  FAIL access log: $sent sends, $leaked request lines with a mailbox"; exit 1; }
  fi
  if [ "$IMPL" = go ]; then
    echo "== signed releases (service worker)"
    go build -o "$TMP/lwr" ./cmd/lullwire-release
    cp -r web "$TMP/sweb"
    "$TMP/lwr" keygen -key "$TMP/k1.pem" -dir "$TMP/sweb" >/dev/null && "$TMP/lwr" sign 0.6.0 -key "$TMP/k1.pem" -dir "$TMP/sweb" >/dev/null
    "$TMP/lullwire-relay" -addr "localhost:$((PORT+3))" -data "$TMP/swdata" -web "$TMP/sweb" >>"$TMP/server.log" 2>&1 &
    SWPID=$!
    for _ in $(seq 50); do curl -s -o /dev/null "http://localhost:$((PORT+3))/index.html" && break; sleep 0.1; done
    BASE="http://localhost:$((PORT+3))/index.html" WEB="$TMP/sweb" LWR="$TMP/lwr" KEY="$TMP/k1.pem" KEY2="$TMP/k2.pem" python3 tests/sw.py || { kill $SWPID; exit 1; }
    kill $SWPID 2>/dev/null || true
    echo "== upgrade from Hush Relay 0.5"
    mkdir -p "$TMP/old" "$TMP/site"
    if git cat-file -e 805d966 2>/dev/null; then
      git archive 805d966 web | tar -x -C "$TMP/old"
      "$TMP/lullwire-relay" -addr "localhost:$((PORT+4))" -data "$TMP/updata" -web "$TMP/site" >>"$TMP/server.log" 2>&1 &
      UPPID=$!
      sleep 0.5
      BASE="http://localhost:$((PORT+4))/index.html" SITE="$TMP/site" OLD="$TMP/old/web" NEW="$PWD/web" python3 tests/upgrade.py || { kill $UPPID; exit 1; }
      kill $UPPID 2>/dev/null || true
    else
      echo "  skipped: the 0.5.0 commit (805d966) is not in this clone"
    fi
  fi
fi
echo "All tests passed."
