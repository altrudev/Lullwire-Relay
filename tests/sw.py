# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Signed releases in the browser, run via tests/run.sh --go --e2e.
WEB is a signed copy of web/ served by the relay from disk; LWR is the release tool,
KEY its key and KEY2 a different key. The test changes files under WEB the way a
compromised server would, and checks that the app only ever runs signed code."""
import os, sys, shutil, subprocess, time
from playwright.sync_api import sync_playwright

U, WEB, LWR, KEY, KEY2 = (os.environ[k] for k in ('BASE', 'WEB', 'LWR', 'KEY', 'KEY2'))
fails = []
def check(ok, what):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok: fails.append(what)
def append(name, text):
    with open(os.path.join(WEB, name), 'a') as f: f.write(text)
def sign(version, key=KEY):
    subprocess.run([LWR, 'sign', version, '-key', key, '-dir', WEB], check=True, capture_output=True)

with sync_playwright() as pw:
    b = pw.chromium.launch()
    ctx = b.new_context(bypass_csp=True)
    p = ctx.new_page()
    p.goto(U)
    p.wait_for_function("navigator.serviceWorker && navigator.serviceWorker.controller", timeout=20000)
    p.reload(); p.wait_for_function("document.body.dataset.ready === '1'")
    build = lambda: p.evaluate("window.__lullwireBuild()")
    p.wait_for_function("/signed release/.test(window.__lullwireBuild())", timeout=10000)
    check('0.6.0' in build(), 'running a verified release: ' + build())
    force = lambda: p.evaluate("navigator.serviceWorker.controller.postMessage({q:'status', check:true})")

    # 1. The server changes app.js without signing: the app keeps running the signed copy.
    append('app.js', '\nwindow.__tampered = 1;\n')
    p.reload(); p.wait_for_function("document.body.dataset.ready === '1'")
    check(p.evaluate("window.__tampered") is None, 'unsigned change to app.js is not run')

    # 2. A properly signed newer release is staged, then used from the next start.
    append('app.js', '\nwindow.__v061 = 1;\n'); sign('0.6.1')
    force(); p.wait_for_function("/0\\.6\\.1 is ready/.test(window.__lullwireBuild())", timeout=15000)
    p.reload(); p.wait_for_function("document.body.dataset.ready === '1'")
    p.evaluate("navigator.serviceWorker.controller.postMessage({q:'status'})"); time.sleep(0.5)
    check(p.evaluate("window.__v061") == 1 and 'Version 0.6.1' in build(), 'signed update applied on the next start')

    # 3. A newer release signed with another key is refused.
    append('app.js', '\nwindow.__forged = 1;\n')
    forge = WEB + '-forge'; shutil.rmtree(forge, ignore_errors=True); shutil.copytree(WEB, forge)
    subprocess.run([LWR, 'keygen', '-key', KEY2, '-dir', forge], check=True, capture_output=True)
    subprocess.run([LWR, 'sign', '0.6.2', '-key', KEY2, '-dir', forge], check=True, capture_output=True)
    shutil.copy(os.path.join(forge, 'release.json'), os.path.join(WEB, 'release.json'))
    force(); p.wait_for_function("/Refused an update/.test(window.__lullwireBuild())", timeout=15000)
    p.reload(); p.wait_for_function("document.body.dataset.ready === '1'")
    check(p.evaluate("window.__forged") is None and 'Version 0.6.1' in build(), 'release signed by another key refused: ' + build())

    # 4. An older (validly signed) release can't roll the app back.
    sign('0.6.0')
    force(); time.sleep(2)
    p.reload(); p.wait_for_function("document.body.dataset.ready === '1'")
    p.evaluate("navigator.serviceWorker.controller.postMessage({q:'status'})"); time.sleep(0.5)
    check('Version 0.6.1' in build() and 'older release' in build(), 'rollback to an older signed release refused: ' + build())
    b.close()

print('  signed releases:', 'FAILED' if fails else 'all passed')
sys.exit(1 if fails else 0)
