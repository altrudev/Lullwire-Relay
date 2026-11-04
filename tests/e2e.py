# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-browser end-to-end test, run via tests/run.sh --e2e:
joining from an invite link (invite-only relay), adding a contact by QR picture,
live chat, verifying a safety code, recovery words, moving a profile by QR,
recovering on another device, and (on relays that support it) an encrypted
video call with simulated cameras."""
import hashlib, os, sys, tempfile, time, zlib, struct
from playwright.sync_api import sync_playwright

U = os.environ.get('BASE', 'http://localhost:8099/index.html')
JOIN = os.environ.get('JOIN', '')
S = tempfile.mkdtemp() + '/'
CHROME = os.environ.get('CHROME')
errs, dialogs = [], []

def page(b, tag, url=U):
    ctx = b.new_context(bypass_csp=True)  # the app's CSP forbids eval; the test harness needs it
    ctx.grant_permissions(['camera', 'microphone'])
    p = ctx.new_page()
    p.on('pageerror', lambda e: errs.append(tag + ': ' + str(e)))
    p.on('console', lambda m: m.type == 'error' and errs.append(tag + ' console: ' + m.text))
    p.on('dialog', lambda d: (dialogs.append(tag + ': ' + d.message), d.accept()))
    p.goto(url)
    return p

def create(p, name):
    p.wait_for_function("document.body.dataset.setup === 'ready'")  # relay requirements are known
    p.fill('#nameIn', name)
    if p.is_visible('#joinIn'): p.fill('#joinIn', JOIN)
    p.click('#createBtn'); p.wait_for_selector('#vList:not([hidden]), #vChat:not([hidden])', timeout=15000)

def home(p):
    while p.is_visible('#back'): p.click('#back')

def chat_with(p, name):
    home(p); p.click(f'.contact:has-text("{name}")'); p.wait_for_selector('#vChat:not([hidden])')

def say(p, text):
    p.fill('#txt', text); p.click('#composer .send')

with sync_playwright() as pw:
    args = ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--autoplay-policy=no-user-gesture-required']
    b = pw.chromium.launch(executable_path=CHROME, args=args) if CHROME else pw.chromium.launch(args=args)

    # 1. Alice signs up; Bob joins straight from her invite link (join code travels in it).
    A = page(b, 'A'); create(A, 'Alice')
    A.click('#inviteBtn'); A.wait_for_function("document.querySelector('#inviteQR').naturalWidth>0")
    link = A.input_value('#inviteLink')
    A.locator('#inviteQR').screenshot(path=S + 'invite.png')
    B = page(b, 'B', link)
    B.wait_for_selector('#invitedBy:not([hidden])'); B.wait_for_function("document.body.dataset.setup === 'ready'")
    join_hidden = not B.is_visible('#joinIn')
    B.fill('#nameIn', 'Bob'); B.click('#createBtn'); B.wait_for_selector('#vChat:not([hidden])', timeout=15000)
    print('1 invite link: Bob joined and is chatting with', B.text_content('#title'), '| join code hidden (came in the invite):', join_hidden)
    home(A); A.wait_for_selector('.contact:has-text("Bob")', timeout=15000)
    print('  Alice sees Bob as a contact, not a request:', A.locator('.contact:has-text("Bob") .tag').count() == 0)

    # 1b. Tampered invites (review 2026-11-02 #3): a swapped mailbox is refused; an invite
    # without a signed card (as from Hush Relay 0.5) is added only after a warning.
    import base64, json as _json
    def tamper(link, fn):
        head, data = link.split('#i=')
        o = _json.loads(base64.urlsafe_b64decode(data + '=' * (-len(data) % 4))); fn(o)
        return head + '#i=' + base64.urlsafe_b64encode(_json.dumps(o).encode()).decode().rstrip('=')
    T = page(b, 'T'); create(T, 'Tess')
    n0 = len(dialogs)
    for lnk in (tamper(link, lambda o: o.update(b='0' * 32)), tamper(link, lambda o: o.pop('q'))):
        home(T); T.click('#addLinkBtn'); T.fill('#addIn', lnk); T.click('#addBtn'); time.sleep(1.5)
    d = dialogs[n0:]
    print('1b swapped mailbox refused:', any('changed or damaged' in x for x in d), '| unsigned invite warned first:', any('older app' in x for x in d))
    if not (any('changed or damaged' in x for x in d) and any('older app' in x for x in d)): errs.append('invite tamper checks: %s' % d)
    home(T); n_alice = T.locator('.contact:has-text("Alice")').count()
    if n_alice != 1: errs.append('expected exactly one Alice after the tampered invites, got %d' % n_alice)

    # 2. Carol already has a profile and adds Alice by scanning a picture of her QR.
    C = page(b, 'C'); create(C, 'Carol')
    C.click('#scanBtn'); C.set_input_files('#scanFile', S + 'invite.png'); C.wait_for_selector('#vChat:not([hidden])')
    print('2 QR picture: Carol is chatting with', C.text_content('#title'))

    # 3. Live delivery both ways.
    home(A); time.sleep(1)
    say(B, 'hello alice'); t = time.time()
    A.wait_for_selector('.contact:has-text("Bob") .badge', timeout=10000); print('3 live delivery: %.1fs' % (time.time() - t))
    chat_with(A, 'Bob'); say(A, 'hi bob'); t = time.time()
    B.wait_for_selector('.m.in:has-text("hi bob")', timeout=10000); print('  reply live: %.1fs' % (time.time() - t))

    # 3b. Bob's phone loses the network. Browsers keep connections that are already open when
    # they go offline, so drop Bob's (the 'online' event does that, like a phone waking up)
    # while he can't make new ones. The status bar says so; mail sent meanwhile waits on the
    # relay; when the network is back he reconnects at once, not after the retry delay
    # (several seconds by then), and the bar clears.
    B.context.set_offline(True)
    B.wait_for_selector('#netBar:not([hidden])', timeout=10000)
    offline_text = B.text_content('#netText')
    B.evaluate("window.dispatchEvent(new Event('online'))")
    say(A, 'sent while bob was offline')
    time.sleep(12)  # long enough for the retry delay to grow past the point being tested
    early = B.locator('.m.in:has-text("sent while bob was offline")').count()
    t = time.time(); B.context.set_offline(False)
    B.wait_for_selector('.m.in:has-text("sent while bob was offline")', timeout=20000); back = time.time() - t
    B.wait_for_selector('#netBar', state='hidden', timeout=10000)
    print('3b offline shown as: "%s" | cut off for real: %s | back online: message in %.1fs, bar cleared' % (offline_text, early == 0, back))
    if 'internet' not in offline_text: errs.append('offline bar said: ' + offline_text)
    if early: errs.append('the message arrived while Bob was offline: the test did not cut him off')
    if back > 6: errs.append('reconnect after the network returned took %.1fs' % back)

    # 3c. The relay can't be reached while the network is up (long-polling relays; the Go
    # relay's live connection isn't affected by request routing): "Offline. Retrying in N s"
    # with Retry, and Retry reconnects straight away instead of waiting out N.
    if not B.is_visible('#voiceBtn'):
        B.route('**/relay.php?a=get*', lambda r: r.abort())
        B.evaluate("window.dispatchEvent(new Event('online'))")  # drop the current long-poll now
        B.wait_for_function("/Retrying in ([5-9]|[1-9][0-9]) s/.test(document.querySelector('#netText').textContent)", timeout=60000)
        retry_text = B.text_content('#netText'); retry_shown = B.is_visible('#netRetry')
        say(A, 'after retry'); time.sleep(0.3)
        B.unroute('**/relay.php?a=get*'); B.click('#netRetry'); t = time.time()
        B.wait_for_selector('.m.in:has-text("after retry")', timeout=20000); back = time.time() - t
        B.wait_for_selector('#netBar', state='hidden', timeout=10000)
        print('3c relay unreachable shown as: "%s", Retry button: %s | Retry -> message in %.1fs' % (retry_text, retry_shown, back))
        if not retry_shown: errs.append('no Retry button while offline')
        if back > 4: errs.append('Retry took %.1fs' % back)
    else:
        print('3c relay unreachable: skipped (live connection relay)')

    # 3d. Files: Bob sends Alice a photo and a document. Both arrive whole (same SHA-256),
    # the photo shows a preview, and Save hands Alice the exact bytes.
    def png(w, h):
        rows = b''.join(b'\x00' + b''.join(bytes([(x * 9) % 256, (y * 5) % 256, 160]) for x in range(w)) for y in range(h))
        chunk = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
        return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b'')
    photo, doc = png(320, 200), os.urandom(1024 * 1024 + 4321)
    files = {'photo.png': photo, 'notes.bin': doc}
    for name, data in files.items():
        with open(S + name, 'wb') as f: f.write(data)
    chat_with(A, 'Bob')
    t = time.time()
    for name in files:
        B.set_input_files('#fileIn', S + name)
        B.wait_for_selector('.m.out .file:has-text("%s"):has-text("sent")' % name, timeout=60000)
    for name in files:
        A.wait_for_selector('.m.in .file:has-text("%s"):has-text("received")' % name, timeout=60000)
    took = time.time() - t
    got = {f['name']: f for f in A.evaluate("window.__lullwireFiles()")}
    same = all(got.get(n, {}).get('sha') == hashlib.sha256(d).hexdigest() and got[n]['state'] == 'done' for n, d in files.items())
    A.wait_for_function("(() => { const i = document.querySelector('.m.in .file-img'); return i && i.naturalWidth === 320; })()", timeout=15000)
    with A.expect_download() as dl:
        A.click('.m.in .file:has-text("notes.bin") .file-save')
    saved = open(dl.value.path(), 'rb').read()
    print('3d files: photo and 1 MB document in %.1fs | identical on arrival: %s | photo preview shown | Save gives the same bytes: %s' % (took, same, saved == doc))
    if not same: errs.append('received files differ: %s' % got)
    if saved != doc: errs.append('saved file differs from the one sent')

    # 4. Verify the safety code.
    A.click('#trustBar'); A.wait_for_selector('#vSafety:not([hidden])')
    codeA = A.text_content('#safetyGrid')
    B.click('#trustBar'); codeB = B.text_content('#safetyGrid')
    A.click('#verifyBtn'); A.wait_for_selector('#vChat:not([hidden])')
    print('4 safety codes match on both phones:', codeA == codeB, '| subtitle now:', A.text_content('#subtitle'))
    B.click('#back')

    # 5. Recovery words.
    home(A); A.click('#settingsBtn'); A.click('#recStart'); words = A.text_content('#recWords')
    A.fill('#recConfirm', words); A.click('#recSave'); A.wait_for_selector('#recOn:not([hidden])', timeout=15000)
    print('5 recovery words on:', words)

    # 6. Move Alice's profile to a new phone (D) by scanning a picture of its move code.
    D = page(b, 'D'); D.click('#pairBtn'); D.wait_for_function("document.querySelector('#pairQR').naturalWidth>0")
    D.locator('#pairQR').screenshot(path=S + 'pair.png'); dcode = D.text_content('#pairCode')
    home(A); A.click('#scanBtn'); A.set_input_files('#scanFile', S + 'pair.png'); A.wait_for_selector('#vLink:not([hidden])')
    print('6 move codes match:', dcode == A.text_content('#linkCode'), dcode)
    A.click('#linkApprove')
    D.wait_for_selector('#vList:not([hidden])', timeout=30000); D.wait_for_selector('.contact:has-text("Bob")')
    A.wait_for_selector('#vSetup:not([hidden])', timeout=30000)
    print('  new phone has the contacts; old phone signed out:', A.is_visible('#vSetup'))
    chat_with(D, 'Bob'); say(D, 'from my new phone')
    B.wait_for_selector('.m.in:has-text("from my new phone")', timeout=15000)
    print('  Bob sees the new-device notice:', B.locator('.m.sys:has-text("new device")').count() > 0)
    say(B, 'got it'); D.wait_for_selector('.m.in:has-text("got it")', timeout=15000); print('  both ways after the move: OK')

    # 7. Recover on yet another phone (E) with the words.
    E = page(b, 'E'); E.fill('#recoverWords', words); E.click('#recoverBtn')
    E.wait_for_selector('.contact:has-text("Bob")', timeout=30000); print('7 recovered with words: OK')
    chat_with(E, 'Bob'); say(E, 'recovered'); B.wait_for_selector('.m.in:has-text("recovered")', timeout=15000); print('  E -> Bob: OK')

    # 8. Encrypted video call (relays with call support only).
    if E.is_visible('#videoBtn'):
        E.click('#videoBtn')
        B.wait_for_selector('#vCall:not([hidden]) #callBarIncoming:not([hidden])', timeout=15000)
        print('8 Bob is ringing:', B.text_content('#callState'))
        B.click('#callAccept')
        for p in (B, E): p.wait_for_function("/^\\d+:\\d\\d$/.test(document.querySelector('#callState').textContent)", timeout=20000)
        time.sleep(4)
        def picture(p):  # how much the remote video varies (a black screen is 0)
            return p.evaluate("""() => { const c = document.querySelector('#remoteCanvas'), d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
              let s = 0, s2 = 0, n = 0; for (let i = 0; i < d.length; i += 400) { const v = d[i] + d[i+1] + d[i+2]; s += v; s2 += v*v; n++; } return Math.sqrt(s2/n - (s/n)**2); }""")
        stats = {k: p.evaluate('window.__lullwireCallStats && window.__lullwireCallStats()') for k, p in (('Bob', B), ('E', E))}
        print('  live on both sides; video picture variance Bob=%.0f E=%.0f' % (picture(B), picture(E)))
        print('  frames:', stats)
        ok = all(s and s['recvAudio'] > 50 and s['recvVideo'] > 20 and s['drawn'] > 20 and s['bad'] == 0 for s in stats.values())
        print('  audio and video flowing both ways, nothing failed to decrypt:', ok)
        if not ok: errs.append('call media did not flow: %s' % stats)
        B.click('#callEnd')
        E.wait_for_selector('#vCall', state='hidden', timeout=10000)
        E.wait_for_selector('.m.sys:has-text("Video call ·")', timeout=10000)
        print('  hang-up reached the other side; call noted in chat:', E.locator('.m.sys:has-text("Video call ·")').first.text_content())
    else:
        print('8 calls: skipped (this relay has no call support)')
    b.close()

# 400s are the deliberate relay probes (over HTTP/2 the browser logs no reason phrase: "400 ()").
real = [e for e in errs if 'status of 400 (' not in e]
# Steps 3b/3c cut Bob off on purpose; the browser logs those failed requests.
real = [e for e in real if not (e.startswith('B console:') and ('net::ERR_INTERNET_DISCONNECTED' in e or 'net::ERR_FAILED' in e))]
print('  dialogs:', dialogs); print('  errors:', real or 'none')
sys.exit(1 if real else 0)
