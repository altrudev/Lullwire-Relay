# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Browser test of notifications, run via tests/run.sh --go --e2e: the settings,
a popup for a message while the app is in the background (generic, then with
names), none while it's in front, and the service worker's popup for a push
signal (delivered through Chrome's DevTools protocol, since a test browser has no
real push service). run.sh serves an unsigned copy of the app, so its service worker
installs even when the app has changed since the last signed release."""
import os, sys, time
from playwright.sync_api import sync_playwright

U = os.environ['BASE']
CHROME = os.environ.get('CHROME')
errs, failed = [], []

def check(what, ok):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok: failed.append(what)

def page(b, tag, url=U, notify=False):
    ctx = b.new_context(bypass_csp=True, permissions=['notifications'] if notify else [])
    p = ctx.new_page()
    p.on('pageerror', lambda e: errs.append(tag + ': ' + str(e)))
    p.on('dialog', lambda d: (errs.append(tag + ' dialog: ' + d.message) if 'Could not' not in d.message else None, d.accept()))
    p.goto(url)
    return p

def home(p):
    while p.is_visible('#back'): p.click('#back')

SHOWN = "(async () => (await (await navigator.serviceWorker.ready).getNotifications()).map(n => n.title + ' | ' + n.body))()"
CLEAR = "(async () => (await (await navigator.serviceWorker.ready).getNotifications()).forEach(n => n.close()))()"

def shown(p, want, timeout=50):  # long enough for a long-poll cycle if the live connection is reconnecting
    end = time.time() + timeout
    while time.time() < end:
        got = p.evaluate(SHOWN)
        if any(want in g for g in got): return got
        p.wait_for_timeout(200)
    return p.evaluate(SHOWN)

def hide(p, hidden):  # what the page reads when it's in the background
    p.evaluate("h => Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => h ? 'hidden' : 'visible' })", hidden)

with sync_playwright() as pw:
    # The full Chromium: the headless-only build always says notifications are denied.
    b = pw.chromium.launch(executable_path=CHROME) if CHROME else pw.chromium.launch(channel='chromium')
    A = page(b, 'A', notify=True); A.wait_for_function("document.body.dataset.setup === 'ready'")
    A.fill('#nameIn', 'Alice'); A.click('#createBtn'); A.wait_for_selector('#vList:not([hidden])', timeout=15000)
    A.click('#inviteBtn'); A.wait_for_function("document.querySelector('#inviteLink').value.includes('#i=')"); link = A.input_value('#inviteLink')
    B = page(b, 'B', link); B.wait_for_selector('#invitedBy:not([hidden])'); B.wait_for_function("document.body.dataset.setup === 'ready'")
    B.fill('#nameIn', 'Bob'); B.click('#createBtn'); B.wait_for_selector('#vChat:not([hidden])', timeout=15000)
    A.evaluate("navigator.serviceWorker.ready.then(() => true)")

    home(A); A.click('#settingsBtn')
    check('settings offer notifications and push (Go relay with push)', A.is_visible('#notifyWrap') and A.is_visible('#pushWrap'))
    check('names option hidden until notifications are on', not A.is_visible('#namesWrap'))
    A.click('#notifyIn')
    try: A.wait_for_selector('#namesWrap:not([hidden])', timeout=8000); ok = A.is_checked('#notifyIn')
    except Exception: ok = False
    check('notifications on; names option shown', ok)
    home(A)

    # In the background: a generic popup.
    hide(A, True)
    B.fill('#txt', 'are you there'); B.click('#composer .send')
    got = shown(A, 'New message')
    check('popup while in the background, without name or text: ' + str(got), any(g == 'Lullwire Relay | New message' for g in got))
    A.evaluate(CLEAR)

    # With names on.
    hide(A, False); A.click('#settingsBtn'); A.click('#namesIn'); home(A); hide(A, True)
    B.fill('#txt', 'dinner at 7'); B.click('#composer .send')
    got = shown(A, 'dinner')
    check('with names on: name and text: ' + str(got), any(g == 'Bob | dinner at 7' for g in got))
    A.evaluate(CLEAR)

    # In front: no popup.
    hide(A, False)
    B.fill('#txt', 'still here'); B.click('#composer .send')
    A.wait_for_selector('.contact:has-text("Bob")'); time.sleep(3)
    check('no popup while the app is in front', A.evaluate(SHOWN) == [])

    # The service worker's popup for a push signal.
    cdp = A.context.new_cdp_session(A)
    regs = []
    cdp.on('ServiceWorker.workerRegistrationUpdated', lambda e: regs.extend(e['registrations']))
    cdp.send('ServiceWorker.enable')
    for _ in range(50):
        if regs: break
        A.wait_for_timeout(100)
    origin = A.evaluate('location.origin')
    reg = next(r for r in regs if not r.get('isDeleted'))
    cdp.send('ServiceWorker.deliverPushMessage', {'origin': origin, 'registrationId': reg['registrationId'], 'data': '{"t":"m"}'})
    got = shown(A, 'New message')
    check('push signal shows "New message" from the service worker: ' + str(got), any(g == 'Lullwire Relay | New message' for g in got))

    # Turning push on in a browser without a push service fails cleanly.
    A.click('#settingsBtn'); A.click('#pushIn'); time.sleep(2)
    check('push unavailable in this test browser: the switch goes back off', not A.is_checked('#pushIn'))

    check('no page errors' + (': ' + str(errs) if errs else ''), not errs)
    b.close()
sys.exit(1 if failed else 0)
