# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Browser test of smaller app behaviours, run via tests/run.sh --go --e2e:
- Create profile first asks whether you already use Lullwire, and Move it here opens
  the move screen (so nobody makes a second account by mistake);
- a chime for a message that isn't on screen, none for the open chat, none with
  Sounds off; ringing for an incoming call that stops once it's declined;
- received messages show when they were sent, plus when they arrived if that was
  much later (Alice's clock runs 7 minutes ahead here, so Bob's messages look late)."""
import os, re, sys, time
from playwright.sync_api import sync_playwright

U = os.environ['BASE']
CHROME = os.environ.get('CHROME')
errs, failed = [], []

def check(what, ok):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok: failed.append(what)

def page(b, tag, url=U, ahead_min=0):
    p = b.new_context(bypass_csp=True).new_page()
    if ahead_min:  # this device's clock runs fast
        p.add_init_script('{ let o = %d; const n = Date.now; Date.now = () => n() + o; window.__skew = x => { o = x; }; }' % (ahead_min * 60000))
    p.on('pageerror', lambda e: errs.append(tag + ': ' + str(e)))
    p.on('dialog', lambda d: d.accept())
    p.goto(url)
    return p

def home(p):
    while p.is_visible('#back'): p.click('#back')

def sounds(p):
    return p.evaluate('window.__lullwireSounds()')

def wait_sound(p, what, n0, timeout=50):
    end = time.time() + timeout
    while time.time() < end:
        if sounds(p)[n0:].count(what): return True
        p.wait_for_timeout(200)
    return False

with sync_playwright() as pw:
    args = ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--autoplay-policy=no-user-gesture-required']
    b = pw.chromium.launch(executable_path=CHROME, args=args) if CHROME else pw.chromium.launch(args=args)

    # 1. "Already use Lullwire?" before a new profile.
    A = page(b, 'A', ahead_min=7); A.wait_for_function("document.body.dataset.setup === 'ready'")
    A.fill('#nameIn', 'Alice'); A.click('#createBtn')
    check('Create profile asks first whether you already use Lullwire', A.is_visible('#dupAsk') and A.is_visible('#vSetup'))
    A.click('#dupMove')
    A.wait_for_selector('#vPair:not([hidden])', timeout=10000)
    A.wait_for_function("document.querySelector('#pairQR').naturalWidth > 0", timeout=10000)
    check('Move it here opens the move screen with the code and steps', A.is_visible('#pairQR') and A.locator('#vPair ol.steps li').count() == 3)
    A.click('#pairCancel'); A.wait_for_selector('#vSetup:not([hidden])')
    A.click('#createBtn'); A.click('#dupNew'); A.wait_for_selector('#vList:not([hidden])', timeout=15000)
    check('I\'m new creates the profile', A.is_visible('#vList'))

    A.click('#inviteBtn'); A.wait_for_function("document.querySelector('#inviteLink').value.includes('#i=')"); link = A.input_value('#inviteLink')
    B = page(b, 'B', link); B.wait_for_selector('#invitedBy:not([hidden])'); B.wait_for_function("document.body.dataset.setup === 'ready'")
    B.fill('#nameIn', 'Bob'); B.click('#createBtn'); B.click('#dupNew'); B.wait_for_selector('#vChat:not([hidden])', timeout=15000)
    home(A); A.wait_for_selector('.contact:has-text("Bob")', timeout=20000)

    # 2. Sounds: a chime for a message that isn't on screen.
    n0 = len(sounds(A))
    B.fill('#txt', 'ding'); B.click('#composer .send')
    check('chime for a message while the chat list is showing', wait_sound(A, 'chime', n0))
    A.click('.contact:has-text("Bob")'); A.wait_for_selector('#vChat:not([hidden])')
    A.wait_for_selector('.m.in:has-text("ding")', timeout=20000)
    n0 = len(sounds(A))
    B.fill('#txt', 'quiet please'); B.click('#composer .send')
    A.wait_for_selector('.m.in:has-text("quiet please")', timeout=50000); time.sleep(0.5)
    check('no chime for a message in the open chat', sounds(A)[n0:].count('chime') == 0)

    # 3. Times: sent time from the sender, plus "arrived" when it came much later.
    label = A.locator('.m.in:has-text("quiet please") .meta, .m.in:has-text("quiet please") small, .m.in:has-text("quiet please") .t').first
    meta = label.text_content() if label.count() else A.locator('.m.in:has-text("quiet please")').inner_text()
    times = re.findall(r'\d{1,2}:\d\d', meta)
    check('received message shows the sent time and when it arrived: ' + repr(meta), 'arrived' in meta and len(times) == 2 and times[0] != times[1])

    # Sounds off: nothing.
    home(A); A.click('#settingsBtn'); A.click('#soundIn'); home(A)
    n0 = len(sounds(A))
    B.fill('#txt', 'silent'); B.click('#composer .send')
    A.click('.contact:has-text("Bob")'); A.wait_for_selector('.m.in:has-text("silent")', timeout=50000); home(A)
    check('no chime with Sounds off', sounds(A)[n0:].count('chime') == 0)
    A.click('#settingsBtn'); A.click('#soundIn'); home(A)

    # 4. Ringing for an incoming call, until it's declined.
    if B.is_visible('#videoBtn'):
        A.evaluate('window.__skew(0)')  # call invitations older than a minute count as missed
        n0 = len(sounds(A))
        B.click('#videoBtn')
        A.wait_for_selector('#vCall:not([hidden]) #callBarIncoming:not([hidden])', timeout=20000)
        A.wait_for_timeout(5600)
        rings = sounds(A)[n0:].count('ring')
        check('incoming call rings and repeats (%d rings in 5.6 s)' % rings, rings >= 3)
        A.click('#callDecline'); A.wait_for_selector('#vCall', state='hidden', timeout=10000)
        n1 = len(sounds(A)); A.wait_for_timeout(3000)
        check('ringing stops once the call is declined', sounds(A)[n1:].count('ring') == 0)
    else:
        print('  skip calls (this relay has no call support)')

    check('no page errors' + (': ' + str(errs) if errs else ''), not errs)
    b.close()
sys.exit(1 if failed else 0)
