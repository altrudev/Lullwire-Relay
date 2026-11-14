# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Browser test of installing the app, run via tests/run.sh --go --e2e: Chrome's own
installability check finds nothing missing; when the browser offers installing, the
chat list shows an Install card whose button opens the browser's dialog; Not now
hides it (Settings still offers it); on iPhone the card says to add it to the Home
Screen and bring the profile over with the backup key (Safari and the Home Screen app
keep separate data); a pasted invite link is taken during setup."""
import os, sys, tempfile
from playwright.sync_api import sync_playwright

U = os.environ['BASE']
CHROME = os.environ.get('CHROME')
errs, failed = [], []
IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1'
OFFER = """(() => { const e = new Event('beforeinstallprompt', { cancelable: true });
  e.prompt = () => { window.__prompted = (window.__prompted || 0) + 1; return Promise.resolve(); };
  e.userChoice = Promise.resolve({ outcome: 'accepted' }); dispatchEvent(e); })()"""

def check(what, ok):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok: failed.append(what)

def start(b, tag, **ctx):
    p = b.new_context(bypass_csp=True, **ctx).new_page()
    p.on('pageerror', lambda e: errs.append(tag + ': ' + str(e)))
    p.on('dialog', lambda d: d.accept())
    p.goto(U); p.wait_for_function("document.body.dataset.setup === 'ready'")
    p.fill('#nameIn', tag); p.click('#createBtn'); p.click('#dupNew'); p.click('#keyLater'); p.wait_for_selector('#vList:not([hidden])', timeout=15000)
    return p

with sync_playwright() as pw:
    b = pw.chromium.launch(executable_path=CHROME) if CHROME else pw.chromium.launch(channel='chromium')
    # Chrome never installs from private windows, so this check uses a normal profile.
    prof = pw.chromium.launch_persistent_context(tempfile.mkdtemp(), channel='chromium', bypass_csp=True) if not CHROME else pw.chromium.launch_persistent_context(tempfile.mkdtemp(), executable_path=CHROME, bypass_csp=True)
    P = prof.new_page(); P.goto(U); P.wait_for_function("document.body.dataset.setup === 'ready'")
    P.evaluate("navigator.serviceWorker.ready.then(() => true)")
    problems = []
    for _ in range(20):  # the service worker needs a moment to be in charge
        problems = prof.new_cdp_session(P).send('Page.getInstallabilityErrors')['installabilityErrors']
        if not problems: break
        P.wait_for_timeout(500)
    check('Chrome finds the app installable: ' + str([p['errorId'] for p in problems]), problems == [])
    prof.close()

    A = start(b, 'A')
    check('no card before the browser offers installing', not A.is_visible('#installCard'))

    A.evaluate(OFFER)
    A.wait_for_selector('#installCard:not([hidden])', timeout=5000)
    check('Install card with a button once the browser offers it', A.is_visible('#installBtn'))
    A.click('#installBtn'); A.wait_for_timeout(300)
    check('Install opens the browser\'s dialog, and the card goes once accepted', A.evaluate('window.__prompted') == 1 and not A.is_visible('#installCard'))

    A.evaluate(OFFER); A.wait_for_selector('#installCard:not([hidden])', timeout=5000)
    A.click('#installClose'); A.wait_for_timeout(300)
    check('Not now hides the card', not A.is_visible('#installCard'))
    A.click('#settingsBtn')
    check('Settings still offers installing', A.is_visible('#installSetBtn'))
    A.click('#installSetBtn'); A.wait_for_timeout(300)
    check('the Settings button opens the dialog too', A.evaluate('window.__prompted') == 2)

    A.click('#back') if A.is_visible('#back') else None
    A.click('#inviteBtn'); A.wait_for_function("document.querySelector('#inviteLink').value.includes('#i=')"); link = A.input_value('#inviteLink')
    # ...and the Home Screen app takes the pasted link.
    K = b.new_context(bypass_csp=True).new_page(); K.goto(U); K.wait_for_function("document.body.dataset.setup === 'ready'")
    K.fill('#pasteInviteIn', link); K.dispatch_event('#pasteInviteIn', 'input')
    check('a pasted invite link is taken during setup', K.is_visible('#invitedBy'))

    I = start(b, 'I', user_agent=IPHONE, viewport={'width': 390, 'height': 800}, is_mobile=True, has_touch=True)
    I.wait_for_selector('#installCard:not([hidden])', timeout=5000)
    hint = I.text_content('#installHint')
    check('iPhone with a profile in Safari: the card says to add it and restore with the backup key: ' + repr(hint),
          'Add to Home Screen' in hint and 'Restore from backup key' in hint and not I.is_visible('#installBtn'))

    check('no page errors' + (': ' + str(errs) if errs else ''), not errs)
    b.close()
sys.exit(1 if failed else 0)
