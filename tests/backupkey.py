# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Browser test of the backup key, run via tests/run.sh --e2e: a new profile offers
to save it; the file restores the profile, with its contacts, on a fresh device (a
new phone, the iPhone Home Screen app, a reinstall), which then chats normally; a
wrong file is refused; Later leaves a reminder card; after Make a new key the old
file no longer works and the new one does. The copy a restore replaces (still open
here) stops receiving: the restored one takes a fresh mailbox and contacts follow it."""
import json, os, sys, tempfile
from playwright.sync_api import sync_playwright

U = os.environ['BASE']
JOIN = os.environ.get('JOIN', '')
CHROME = os.environ.get('CHROME')
DIR = tempfile.mkdtemp()
errs, dialogs, failed = [], [], []

def check(what, ok):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok: failed.append(what)

def page(b, tag, url=U):
    p = b.new_context(bypass_csp=True, accept_downloads=True).new_page()
    p.on('pageerror', lambda e: errs.append(tag + ': ' + str(e)))
    p.on('dialog', lambda d: (dialogs.append(tag + ': ' + d.message), d.accept()))
    p.goto(url); p.wait_for_function("document.body.dataset.setup === 'ready'")
    return p

def home(p):
    while p.is_visible('#back'): p.click('#back')

def save_key(p, button, name):
    with p.expect_download(timeout=20000) as d:
        p.click(button)
    path = os.path.join(DIR, name)
    d.value.save_as(path)
    return path

def restore(b, tag, path):
    p = page(b, tag)
    p.set_input_files('#keyFile', path)
    return p

with sync_playwright() as pw:
    b = pw.chromium.launch(executable_path=CHROME) if CHROME else pw.chromium.launch()

    # 1. A new profile offers its backup key straight away.
    A = page(b, 'A'); A.fill('#nameIn', 'Alice')
    if JOIN: A.fill('#joinIn', JOIN)
    A.click('#createBtn'); A.click('#dupNew')
    A.wait_for_selector('#vKey:not([hidden])', timeout=15000)
    check('a new profile shows Save your backup key', A.is_visible('#keySaveBtn'))
    key1 = save_key(A, '#keySaveBtn', 'alice1.lwkey')
    k = json.load(open(key1))
    check('the file is a backup key naming the relay, nothing else readable', k.get('lullwire') == 'backup-key' and k.get('relay', '').startswith('http') and set(k) == {'lullwire', 'v', 'name', 'relay', 'l', 't', 'k'})
    A.wait_for_selector('#vList:not([hidden])', timeout=10000)
    check('after saving: the chat list, without the reminder', not A.is_visible('#keyCard'))

    # Bob, via Alice's invite; "Later" leaves a reminder.
    A.click('#inviteBtn'); A.wait_for_function("document.querySelector('#inviteLink').value.includes('#i=')"); link = A.input_value('#inviteLink')
    B = page(b, 'B', link); B.wait_for_selector('#invitedBy:not([hidden])')
    B.fill('#nameIn', 'Bob'); B.click('#createBtn'); B.click('#dupNew')
    B.wait_for_selector('#vKey:not([hidden])', timeout=15000); B.click('#keyLater')
    B.wait_for_selector('#vChat:not([hidden])', timeout=15000)
    check('Later goes on to the chat with the person who invited you', B.is_visible('#vChat'))
    home(B); check('Later leaves a Save your backup key card', B.is_visible('#keyCard'))
    B.click('#keyCardBtn'); B.wait_for_selector('#vKey:not([hidden])')  # the card opens the save screen
    bkey = save_key(B, '#keySaveBtn', 'bob.lwkey')
    home(B); check('the card goes once the key is saved', not B.is_visible('#keyCard'))
    home(A); A.wait_for_selector('.contact:has-text("Bob")', timeout=20000)
    A.click('.contact:has-text("Bob")'); A.fill('#txt', 'hi Bob'); A.click('#composer .send')
    B.click('.contact:has-text("Alice")'); B.wait_for_selector('.m.in:has-text("hi Bob")', timeout=30000)

    # 2. Alice on a fresh device: pick the file, and she's back with Bob.
    A.wait_for_timeout(3000)  # the backup updates a moment after contacts change
    A2 = restore(b, 'A2', key1)
    A2.wait_for_selector('#vList:not([hidden])', timeout=30000)
    A2.wait_for_selector('.contact:has-text("Bob")', timeout=10000)
    check('restore from backup key: profile and contacts back on a new device', A2.is_visible('.contact:has-text("Bob")'))
    check('no reminder to save a key that was just used', not A2.is_visible('#keyCard'))
    A2.click('.contact:has-text("Bob")'); A2.fill('#txt', 'back on a new phone'); A2.click('#composer .send')
    B.wait_for_selector('.m.in:has-text("back on a new phone")', timeout=40000)
    B.fill('#txt', 'welcome back'); B.click('#composer .send')
    A2.wait_for_selector('.m.in:has-text("welcome back")', timeout=60000)
    check('the restored profile chats both ways', True)
    # The original copy (still open here) took no part: the restored one has its own mailbox now.
    home(A); A.click('.contact:has-text("Bob")'); A.wait_for_timeout(3000)
    check('the copy it replaced no longer receives', A.locator('.m.in:has-text("welcome back")').count() == 0)

    # 3. A wrong file is refused.
    bad = os.path.join(DIR, 'notes.txt'); open(bad, 'w').write('shopping list')
    X = page(b, 'X'); n0 = len(dialogs); X.set_input_files('#keyFile', bad); X.wait_for_timeout(800)
    check('a file that isn\'t a backup key is refused', any('isn\'t a Lullwire backup key' in d for d in dialogs[n0:]) and X.is_visible('#vSetup'))

    # 4. Make a new key: the old file stops working, the new one works.
    home(A2); A2.click('#settingsBtn')
    with A2.expect_download(timeout=20000) as d:
        A2.click('#keyNewBtn')
    key2 = os.path.join(DIR, 'alice2.lwkey'); d.value.save_as(key2)
    A2.wait_for_timeout(1500)
    Y = page(b, 'Y'); n0 = len(dialogs); Y.set_input_files('#keyFile', key1)
    for _ in range(40):
        if dialogs[n0:]: break
        Y.wait_for_timeout(250)
    check('after Make a new key, the old file no longer restores', any('isn\'t on its relay' in d for d in dialogs[n0:]))
    Z = restore(b, 'Z', key2); Z.wait_for_selector('#vList:not([hidden])', timeout=30000)
    check('the new file restores', Z.is_visible('.contact:has-text("Bob")'))

    # 5. Already using Lullwire? The question on Create profile offers the key first.
    W = page(b, 'W'); W.fill('#nameIn', 'Bob again'); W.click('#createBtn')
    check('Create profile asks first, offering Restore from backup key', W.is_visible('#dupAsk') and W.is_visible('label:has(#keyFile2)'))
    W.set_input_files('#keyFile2', bkey); W.wait_for_selector('#vList:not([hidden])', timeout=30000)
    check('restoring from that question works too', W.is_visible('.contact:has-text("Alice")'))

    check('no page errors' + (': ' + str(errs) if errs else ''), not errs)
    b.close()
sys.exit(1 if failed else 0)
