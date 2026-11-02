# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Upgrading from Hush Relay 0.5 in the browser, run via tests/run.sh --go --e2e.
SITE is the folder the relay serves; OLD and NEW hold the 0.5 and current app.
Alice and Bob start on 0.5; the site switches to the new app and only Alice reloads,
so a 0.6 user and a 0.5 user talk to each other. Then: the app lock, and Bob updates."""
import os, sys, shutil, time
from playwright.sync_api import sync_playwright

U, SITE, OLD, NEW = (os.environ[k] for k in ('BASE', 'SITE', 'OLD', 'NEW'))
fails, errs, dialogs = [], [], []
def check(ok, what):
    print(('  ok   ' if ok else '  FAIL ') + what)
    if not ok: fails.append(what)
def serve(src):
    for n in os.listdir(SITE):
        p = os.path.join(SITE, n)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    for n in os.listdir(src):
        s = os.path.join(src, n)
        (shutil.copytree if os.path.isdir(s) else shutil.copy)(s, os.path.join(SITE, n))
def page(b, tag, url=U):
    ctx = b.new_context(bypass_csp=True)
    p = ctx.new_page()
    p.on('pageerror', lambda e: errs.append(tag + ': ' + str(e)))
    p.on('dialog', lambda d: (dialogs.append(tag + ': ' + d.message), d.accept(p.__dict__.get('answer', ''))))
    p.goto(url)
    return p
def home(p):
    while p.is_visible('#back'): p.click('#back')
def chat_with(p, name):
    home(p); p.click(f'.contact:has-text("{name}")'); p.wait_for_selector('#vChat:not([hidden])')
def say(p, text):
    p.fill('#txt', text); p.click('#composer .send')
def fresh_load(p):  # new code, bypassing any service worker cache
    p.evaluate("navigator.serviceWorker && navigator.serviceWorker.getRegistrations().then(rs => Promise.all(rs.map(r => r.unregister())))")
    p.reload(); p.wait_for_load_state()

serve(OLD)
with sync_playwright() as pw:
    b = pw.chromium.launch()
    # Hush Relay 0.5: Alice and Bob chat.
    A = page(b, 'A'); A.wait_for_function("document.body.dataset.setup === 'ready'")
    A.fill('#nameIn', 'Alice'); A.click('#createBtn'); A.wait_for_selector('#vList:not([hidden])')
    A.click('#inviteBtn'); A.wait_for_function("document.querySelector('#inviteQR').naturalWidth>0")
    B = page(b, 'B', A.input_value('#inviteLink'))
    B.wait_for_selector('#invitedBy:not([hidden])'); B.wait_for_function("document.body.dataset.setup === 'ready'")
    B.fill('#nameIn', 'Bob'); B.click('#createBtn'); B.wait_for_selector('#vChat:not([hidden])')
    say(B, 'hello from 0.5'); home(A); A.wait_for_selector('.contact:has-text("Bob")', timeout=15000)
    chat_with(A, 'Bob'); A.wait_for_selector('.m.in:has-text("hello from 0.5")', timeout=15000)
    say(A, 'secret history line'); B.wait_for_selector('.m.in:has-text("secret history line")', timeout=15000)
    check(A.evaluate("indexedDB.databases().then(d => d.map(x => x.name))").count('hush2') == 1, 'both on Hush Relay 0.5 and chatting')

    # The site updates; Alice reloads into Lullwire (Bob stays on 0.5).
    serve(NEW)
    fresh_load(A); A.wait_for_function("document.body.dataset.ready === '1'", timeout=20000)
    A.wait_for_selector('.contact:has-text("Bob")', timeout=15000)
    dbs = A.evaluate("indexedDB.databases().then(d => d.map(x => x.name))")
    check('hush2' not in dbs and 'lullwire' in dbs, 'profile moved into the encrypted vault; the 0.5 database is gone: %s' % dbs)
    chat_with(A, 'Bob')
    try:
        A.wait_for_selector('.m:has-text("secret history line")', timeout=10000)
        hist = A.locator('.m:has-text("secret history line")').count() == 1 and A.locator('.m:has-text("hello from 0.5")').count() == 1
    except Exception: hist = False
    check(hist, 'chat history came along')
    raw = A.evaluate("""() => new Promise(res => { const r = indexedDB.open('lullwire'); r.onsuccess = () => {
        const out = []; const t = r.result.transaction(['kv', 'contacts', 'messages', 'meta']);
        for (const s of ['kv', 'contacts', 'messages', 'meta']) t.objectStore(s).getAll().onsuccess = e => out.push(...e.target.result);
        t.oncomplete = () => res(JSON.stringify(out, (k, v) => v instanceof Uint8Array ? new TextDecoder().decode(v) : v)); }; })""")
    check('secret history line' not in raw and 'Alice' not in raw and 'Bob' not in raw, 'nothing readable in the stored records (%d bytes checked)' % len(raw))
    B.wait_for_selector('.m.sys:has-text("new device")', timeout=15000)
    check(True, 'Bob (0.5) was told the session renewed')
    say(A, 'from lullwire to 0.5'); B.wait_for_selector('.m.in:has-text("from lullwire to 0.5")', timeout=15000)
    say(B, 'from 0.5 to lullwire'); A.wait_for_selector('.m.in:has-text("from 0.5 to lullwire")', timeout=15000)
    check(True, 'Lullwire and Hush Relay 0.5 message both ways after the upgrade')
    try: A.wait_for_function("window.__lullwireDelivery() === 'socket'", timeout=40000); sock = True
    except Exception: sock = False
    check(sock, 'delivery uses the live connection')

    # App lock: a new vault key, and everything re-encrypted with it (review 2026-11-02 #12).
    snap = lambda: A.evaluate("""() => new Promise(res => { const r = indexedDB.open('lullwire'); r.onsuccess = () => {
        const t = r.result.transaction(['meta', 'kv']); const o = {};
        t.objectStore('meta').get('vault').onsuccess = e => o.h = e.target.result;
        t.objectStore('kv').get('me').onsuccess = e => o.me = Array.from(e.target.result.d).join(',');
        t.oncomplete = () => { r.result.close(); res(o); }; }; })""")
    before = snap()
    home(A); A.click('#settingsBtn'); A.fill('#lp1', 'correct horse 1'); A.fill('#lp2', 'correct horse 1'); A.click('#lockOnBtn')
    A.wait_for_selector('#lockOn:not([hidden])', timeout=20000)
    after = snap()
    check(before['h']['mode'] == 'plain' and after['h']['mode'] == 'pass' and 'mk' not in after['h'] and before['me'] != after['me'],
          'turning on the lock re-encrypts everything with a new key')
    A.reload(); A.wait_for_selector('#vLock:not([hidden])', timeout=15000)
    A.fill('#unlockIn', 'wrong horse 1'); A.click('#unlockBtn'); time.sleep(3)
    check(A.is_visible('#vLock') and any('not right' in d for d in dialogs), 'locked after a restart; a wrong passphrase is refused')
    A.fill('#unlockIn', 'correct horse 1'); A.click('#unlockBtn')
    A.wait_for_selector('.contact:has-text("Bob")', timeout=20000)
    check(True, 'the right passphrase opens it')
    A.answer = 'correct horse 1'
    A.click('#settingsBtn'); A.click('#lockOffBtn'); A.wait_for_selector('#lockOff:not([hidden])', timeout=20000)
    A.reload(); A.wait_for_selector('.contact:has-text("Bob")', timeout=15000)
    check(not A.is_visible('#vLock'), 'app lock turned off again')

    # Bob updates too; both on Lullwire, still talking.
    fresh_load(B); B.wait_for_function("document.body.dataset.ready === '1'", timeout=20000)
    chat_with(B, 'Alice'); say(B, 'both on lullwire')
    chat_with(A, 'Bob'); A.wait_for_selector('.m.in:has-text("both on lullwire")', timeout=15000)
    say(A, 'v4 now'); B.wait_for_selector('.m.in:has-text("v4 now")', timeout=15000)
    check(True, 'after both update: messages both ways')

    # An interrupted move into the vault resumes (review 2026-11-02 #4): a 0.5 store with
    # 3000 messages, the page closed while moving, then opened again.
    ctx = b.new_context(bypass_csp=True); S = ctx.new_page(); S.on('dialog', lambda d: d.accept())
    with open(os.path.join(SITE, 'seed.html'), 'w') as f: f.write('<!doctype html><title>seed</title>')
    S.goto(U.replace('index.html', 'seed.html'))
    S.evaluate("""async () => {
      const hex = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, '0')).join('');
      const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
      const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
      const bob = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
      const secret = hex(crypto.getRandomValues(new Uint8Array(32)));
      const box = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret))).slice(0, 32);
      const bobRaw = await crypto.subtle.exportKey('raw', bob.publicKey), bobId = hex(await crypto.subtle.digest('SHA-256', bobRaw)).slice(0, 32);
      const db = await new Promise(res => { const r = indexedDB.open('hush2', 1); r.onupgradeneeded = () => { const d = r.result;
        d.createObjectStore('kv'); d.createObjectStore('contacts', { keyPath: 'id' });
        d.createObjectStore('messages', { keyPath: 'id', autoIncrement: true }).createIndex('contact', 'contact'); }; r.onsuccess = () => res(r.result); });
      const t = db.transaction(['kv', 'contacts', 'messages'], 'readwrite');
      t.objectStore('kv').put({ priv: kp.privateKey, pub: b64(await crypto.subtle.exportKey('raw', kp.publicKey)), secret, box, name: 'Seed',
        relay: location.origin + '/relay.php', inviteTok: 'tok' }, 'me');
      t.objectStore('contacts').put({ id: bobId, pub: b64(bobRaw), box: '1'.repeat(32), relay: location.origin + '/relay.php', name: 'Bobby',
        unread: 0, ts: Date.now(), verified: false, blocked: false, sessions: {}, active: null, last: '' });
      for (let i = 0; i < 3000; i++) t.objectStore('messages').put({ contact: bobId, dir: 'in', txt: 'old ' + i, ts: Date.now() });
      await new Promise(r => t.oncomplete = r); db.close(); }""")
    S.goto(U); time.sleep(0.6); S.close()          # closed while moving
    S = ctx.new_page(); S.on('dialog', lambda d: d.accept()); S.goto(U)
    S.wait_for_function("document.body.dataset.ready === '1'", timeout=60000)
    S.wait_for_selector('.contact:has-text("Bobby")', timeout=15000)
    count = S.evaluate("""() => new Promise(res => { const r = indexedDB.open('lullwire'); r.onsuccess = () => {
        const q = r.result.transaction('messages').objectStore('messages').count(); q.onsuccess = () => { r.result.close(); res(q.result); }; }; })""")
    dbs = S.evaluate("indexedDB.databases().then(d => d.map(x => x.name))")
    check(count == 3000 and 'hush2' not in dbs, 'an interrupted move resumes: %d of 3000 messages, databases %s' % (count, dbs))
    b.close()

real = [e for e in errs if '400 (Bad Request)' not in e]
print('  dialogs:', dialogs); print('  errors:', real or 'none')
print('  upgrade:', 'FAILED' if fails or real else 'all passed')
sys.exit(1 if fails or real else 0)
