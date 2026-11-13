# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Browser test of the relay owner's dashboard, run via tests/run.sh --go --e2e:
claiming the relay with a code from the server, switching the shared join code
off, single-use invites (used once, refused the second time, members' invites don't
admit anyone), names matched from contacts, moving a member's profile after the
shared code is off, removing a member, and restarting the relay."""
import os, subprocess, sys, tempfile, time
from playwright.sync_api import sync_playwright

U = os.environ['BASE']
JOIN = os.environ['JOIN']
BIN, DATA = os.environ['RELAY_BIN'], os.environ['RELAY_DATA']
S = tempfile.mkdtemp() + '/'
CHROME = os.environ.get('CHROME')
errs, dialogs = [], []
failed = []

def check(what, ok):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok: failed.append(what)

def page(b, tag, url=U):
    p = b.new_context(bypass_csp=True, viewport={'width': 430, 'height': 900}, device_scale_factor=2).new_page()
    p.on('pageerror', lambda e: errs.append(tag + ': ' + str(e)))
    p.on('console', lambda m: m.type == 'error' and 'Failed to load resource' not in m.text and errs.append(tag + ' console: ' + m.text))
    p.on('dialog', lambda d: (dialogs.append(tag + ': ' + d.message), d.accept()))
    p.goto(url)
    return p

def wait_dialog(p, tag, n0, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        new = [d for d in dialogs[n0:] if d.startswith(tag + ':')]
        if new: return new[-1]
        p.wait_for_timeout(100)  # lets Playwright deliver the dialog event (time.sleep wouldn't)
    return ''

def home(p):
    while p.is_visible('#back'): p.click('#back')

def owner_code():
    out = subprocess.run([BIN, '-data', DATA, '-owner-code'], capture_output=True, text=True, check=True).stdout
    return out.split('Owner code: ')[1].split()[0]

def dash(p):
    home(p); p.evaluate("document.querySelector('#ownerStats').textContent = ''")  # wait for fresh numbers, not the last visit's
    p.click('#settingsBtn'); p.click('#ownerBtn')
    p.wait_for_selector('#ownerDash:not([hidden]) #ownerStats .stat', timeout=15000)

def stat(p, label):
    return p.locator(f'#ownerStats .stat:has(span:text-is("{label}")) b').text_content()

def members(p):
    return [x.strip() for x in p.locator('#ownerMembers li .grow > div:first-child').all_text_contents()]

def invite(p):
    home(p); p.evaluate("document.querySelector('#inviteLink').value = ''")
    p.click('#inviteBtn'); p.wait_for_function("document.querySelector('#inviteLink').value.includes('#i=')")
    return p.input_value('#inviteLink')

def join_from(b, tag, link, name):
    p = page(b, tag, link)
    p.wait_for_selector('#invitedBy:not([hidden])'); p.wait_for_function("document.body.dataset.setup === 'ready'")
    p.fill('#nameIn', name); n = len(dialogs); p.click('#createBtn')
    try:
        p.wait_for_selector('#vChat:not([hidden])', timeout=8000); return p, True
    except Exception:
        return p, False

with sync_playwright() as pw:
    b = pw.chromium.launch(executable_path=CHROME) if CHROME else pw.chromium.launch()

    # Alice runs the relay; she signed up with its shared code.
    A = page(b, 'A'); A.wait_for_function("document.body.dataset.setup === 'ready'")
    A.fill('#nameIn', 'Alice'); A.fill('#joinIn', JOIN); A.click('#createBtn'); A.wait_for_selector('#vList:not([hidden])', timeout=15000)

    # 1. Claim with a code from the server.
    A.click('#settingsBtn'); check('Owner dashboard offered by a Go relay', A.is_visible('#ownerBtn'))
    A.click('#ownerBtn'); A.wait_for_selector('#ownerClaim:not([hidden])')
    n0 = len(dialogs); A.fill('#ownerCodeIn', 'wrong-code'); A.click('#ownerClaimBtn')
    msg = wait_dialog(A, 'A', n0)
    check('wrong owner code refused (' + msg + ')', 'not accepted' in msg and A.is_visible('#ownerClaim'))
    A.fill('#ownerCodeIn', owner_code()); A.click('#ownerClaimBtn')
    A.wait_for_selector('#ownerDash:not([hidden]) #ownerStats .stat', timeout=15000)
    check('claimed; members list shows only "You"', members(A) == ['You'])
    check('stats: 1 member', stat(A, 'Members') == '1')

    # 2. Switch the shared code off.
    A.click('#ownerSharedIn'); A.wait_for_function("document.querySelector('#ownerSharedHint').textContent.startsWith('Off')", timeout=10000)
    check('shared join code off', not A.is_checked('#ownerSharedIn'))

    # 3. A single-use invite: Bob joins with it; Carol can't reuse it.
    link = invite(A)
    check('invite view says it admits one person', A.is_visible('#inviteOwnerNote'))
    B, ok = join_from(b, 'B', link, 'Bob'); check('Bob joined with the single-use invite', ok)
    C, ok = join_from(b, 'C', link, 'Carol')
    check('Carol refused with the same invite', not ok and any('not accepted' in d for d in dialogs if d.startswith('C:')))
    A2 = invite(A); check('next invite carries a new code', A2 != link)

    # 4. Bob's own invite adds contacts but doesn't let anyone join.
    blink = invite(B)
    D, ok = join_from(b, 'D', blink, 'Dana')
    check('a member\'s invite admits nobody once the shared code is off', not ok)

    # 5. Chat works for Bob (member key) and Alice sees him by name.
    home(A); A.wait_for_selector('.contact:has-text("Bob")', timeout=15000)
    home(B); B.click('.contact:has-text("Alice")'); B.wait_for_selector('#vChat:not([hidden])')
    B.fill('#txt', 'hello owner'); B.click('#composer .send')
    A.click('.contact:has-text("Bob")'); A.wait_for_selector('.m.in:has-text("hello owner")', timeout=15000)
    dash(A)
    got = sorted(members(A)); check('Bob listed by name from Alice\'s contacts ' + str(got), got == ['Bob', 'You'])
    if os.environ.get('SHOT'):  # a picture of the dashboard, for docs
        A.set_viewport_size({'width': 430, 'height': 2700}); A.wait_for_timeout(400)
        A.screenshot(path=os.environ['SHOT'], full_page=True)
    check('stats: 2 members, joins counted today', stat(A, 'Members') == '2' and int(stat(A, 'Joined today')) >= 1)

    # 6. Bob moves to a new phone after the shared code is off (temporary mailboxes).
    home(B); B.click('#back') if B.is_visible('#back') else None
    E = page(b, 'E'); E.click('#pairBtn'); E.wait_for_function("document.querySelector('#pairQR').naturalWidth>0")
    E.locator('#pairQR').screenshot(path=S + 'pair.png')
    home(B); B.click('#scanBtn'); B.set_input_files('#scanFile', S + 'pair.png'); B.wait_for_selector('#vLink:not([hidden])')
    B.click('#linkApprove')
    E.wait_for_selector('#vList:not([hidden])', timeout=30000)
    B.wait_for_selector('#vSetup:not([hidden])', timeout=30000)
    check('Bob moved to a new phone with the shared code off', E.is_visible('#vList'))
    dash(A); check('temporary move mailboxes are not listed as members', sorted(members(A)) == ['Bob', 'You'])

    # 7. Remove Bob.
    A.click('#ownerMembers li:has-text("Bob") button'); A.wait_for_function("!document.querySelector('#ownerMembers').textContent.includes('Bob')", timeout=10000)
    check('Bob removed', members(A) == ['You'] and stat(A, 'Members') == '1')

    # 8. Restart the relay from the app.
    before = A.locator('#ownerServer dd').nth(1).text_content()
    A.click('#ownerRestartBtn'); time.sleep(5)
    A.click('#ownerRefreshBtn'); time.sleep(1)
    check('relay restarted and the dashboard still works (owner kept)', A.is_visible('#ownerDash') and stat(A, 'Members') == '1')

    real = [e for e in errs if 'ERR_CONNECTION_REFUSED' not in e and 'WebSocket' not in e]
    print('  dialogs:', dialogs)
    check('no page errors' + (': ' + str(real) if real else ''), not real)
    b.close()
sys.exit(1 if failed else 0)
