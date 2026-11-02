# Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Renders the brand images in this folder from HTML (needs Playwright + Chromium and
the Inter font). Run: python3 assets/brand/render.py"""
import os, sys
from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
MARK = open(os.path.join(HERE, 'logo-mark.svg')).read().replace('<svg ', '<svg class="mark" ', 1)
INV = open(os.path.join(HERE, 'logo-mark-inverse.svg')).read().replace('<svg ', '<svg class="mark" ', 1)  # on teal
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{--ink:#122029;--muted:#5a6773;--line:#dde4e9;--bg:#f3f6f8;--acc:#0e7a68;--acc-d:#0a5c4f;--acc2:#e3f2ee;--warm:#b45309;--warm2:#fdf3e7}
body{font-family:Inter,sans-serif;color:var(--ink)}
.disp{font-family:'Inter Display',Inter,sans-serif}
code{font-family:'DejaVu Sans Mono',monospace;background:#0f1d24;color:#d7f3ec;padding:3px 8px;border-radius:6px;font-size:.92em}
"""
I = {  # small line icons
 'phone': '<rect x="6" y="2.5" width="12" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>',
 'android': '<rect x="6" y="2.5" width="12" height="19" rx="2.5"/><path d="M9.5 9.5l2 2 3.5-3.5"/>',
 'web': '<circle cx="12" cy="12" r="9.5"/><path d="M2.5 12h19M12 2.5c3 3.2 3 15.8 0 19M12 2.5c-3 3.2-3 15.8 0 19"/>',
 'install': '<path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 17v3h16v-3"/>',
 'link': '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1.2 1.2"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1.2-1.2"/>',
 'user': '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>',
 'shield': '<path d="M12 2.5l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10v-6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
 'video': '<rect x="2.5" y="6" width="13" height="12" rx="2"/><path d="M15.5 10.5l6-3.5v10l-6-3.5"/>',
 'words': '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9h4M13 9h4M7 13h4M13 13h4M7 17h4"/>',
 'server': '<rect x="3" y="4" width="18" height="6.5" rx="1.5"/><rect x="3" y="13.5" width="18" height="6.5" rx="1.5"/><path d="M7 7.25h.01M7 16.75h.01M11 7.25h6M11 16.75h6"/>',
 'eye': '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><path d="M4 4l16 16"/>',
 'lock': '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
 'send': '<path d="M21 3L10 14"/><path d="M21 3l-7 18-4-7-7-4z"/>',
}
def ic(name, size=24, color='#0e7a68', w=2):
    return f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="{w}" stroke-linecap="round" stroke-linejoin="round">{I[name]}</svg>'

LOCKUP = f"""<style>{CSS}body{{width:1200px;height:320px;display:flex;align-items:center;gap:44px;padding:0 40px;background:transparent}}
.mark{{width:240px;height:240px}} .t{{font-size:128px;font-weight:800;letter-spacing:-3.5px;line-height:1}} .t span{{color:var(--acc)}}
.s{{font-size:30px;color:var(--muted);margin-top:12px;letter-spacing:-.2px}}</style>
{MARK}<div><div class="t disp">Lullwire <span>Relay</span></div><div class="s">Private messaging on a relay you own</div></div>"""

SOCIAL = f"""<style>{CSS}body{{width:1280px;height:640px;background:var(--acc);color:#fff;position:relative;overflow:hidden;padding:70px 80px}}
.c1{{position:absolute;right:-160px;top:-200px;width:640px;height:640px;border-radius:50%;background:rgba(255,255,255,.06)}}
.c2{{position:absolute;right:120px;bottom:-260px;width:460px;height:460px;border-radius:50%;background:rgba(255,255,255,.05)}}
.brand{{display:flex;align-items:center;gap:22px;font-size:40px;font-weight:800;letter-spacing:-.8px}}
.brand .mark{{width:84px;height:84px;filter:drop-shadow(0 6px 16px rgba(0,0,0,.18))}}
h1{{font-size:70px;line-height:1.02;font-weight:800;letter-spacing:-2px;margin-top:34px;max-width:900px}}
p{{font-size:26px;line-height:1.4;color:#d4ede7;margin-top:18px;max-width:820px}}
.pills{{position:absolute;left:80px;bottom:52px;display:flex;gap:12px}}
.pill{{display:flex;align-items:center;gap:9px;background:rgba(255,255,255,.14);border-radius:999px;padding:9px 16px;font-size:19px;font-weight:600}}
.phone{{position:absolute;right:96px;top:120px;width:250px;height:440px;background:#fff;border-radius:38px;box-shadow:0 30px 60px rgba(0,0,0,.25);padding:22px 18px;color:var(--ink)}}
.ph-h{{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px;padding-bottom:12px;border-bottom:1px solid var(--line)}}
.av{{width:30px;height:30px;border-radius:50%;background:#2f6db3;color:#fff;display:grid;place-items:center;font-size:14px;font-weight:700}}
.m{{margin-top:12px;padding:9px 12px;border-radius:14px;font-size:14px;max-width:80%;line-height:1.3}}
.in{{background:#eef1f4}} .out{{background:var(--acc);color:#fff;margin-left:auto}}
.call{{margin-top:16px;border-radius:16px;background:#0f1d24;height:120px;display:grid;place-items:center;color:#9fd8c9;font-size:13px;font-weight:600}}
</style><div class="c1"></div><div class="c2"></div>
<div class="brand">{INV}Lullwire Relay</div>
<h1 class="disp">Your messenger.<br>Your server.<br>Your rules.</h1>
<p>End-to-end encrypted chat, voice and video,<br>on a relay you run. Only people you invite get in.</p>
<div class="pills"><span class="pill">{ic('lock',22,'#fff')}Encrypted</span><span class="pill">{ic('video',22,'#fff')}Calls</span><span class="pill">{ic('android',22,'#fff')}Android + web</span><span class="pill">{ic('shield',22,'#fff')}Open source</span></div>
<div class="phone"><div class="ph-h"><span class="av">B</span>Bob<span style="margin-left:auto;display:flex;gap:8px">{ic('video',20)}</span></div>
<div class="m in">Got your invite, I'm in 👋</div><div class="m out">Welcome! Video call?</div><div class="m in">Sure, calling now</div>
<div class="call">{ic('lock',26,'#9fd8c9')}&nbsp;Encrypted video call · 0:42</div></div>"""

BANNER = f"""<style>{CSS}body{{width:1600px;height:480px;background:linear-gradient(120deg,#0e7a68,#0b6556);color:#fff;position:relative;overflow:hidden;display:flex;align-items:center;padding:0 90px;gap:60px}}
.c1{{position:absolute;right:-120px;top:-220px;width:620px;height:620px;border-radius:50%;background:rgba(255,255,255,.06)}}
.mark{{width:220px;height:220px;flex:none;filter:drop-shadow(0 12px 26px rgba(0,0,0,.22))}}
h1{{font-size:92px;font-weight:800;letter-spacing:-2.6px;line-height:1}}
p{{font-size:32px;color:#d4ede7;margin-top:18px;line-height:1.35}}
.row{{display:flex;gap:14px;margin-top:28px}}
.pill{{display:flex;align-items:center;gap:9px;background:rgba(255,255,255,.14);border-radius:999px;padding:10px 18px;font-size:22px;font-weight:600}}
</style><div class="c1"></div>{INV}
<div><h1 class="disp">Lullwire Relay</h1><p>Private chat, voice and video on a relay you own.<br>No phone number. No account. No app store.</p>
<div class="row"><span class="pill">{ic('lock',22,'#fff')}End-to-end encrypted</span><span class="pill">{ic('eye',22,'#fff')}Invite-only relay</span><span class="pill">{ic('android',22,'#fff')}Android · Web</span></div></div>"""

def step(n, icon, title, text):
    return f'<div class="st"><div class="n">{n}</div><div class="si">{ic(icon,22)}</div><div><span class="t">{title}</span><span>{text}</span></div></div>'
INSTALL = f"""<style>{CSS}body{{width:1080px;height:1350px;background:var(--bg);display:flex;flex-direction:column;overflow:hidden}}
header{{flex:none;background:var(--acc);color:#fff;padding:38px 56px 34px;display:flex;align-items:center;gap:22px}}
header .mark{{width:78px;height:78px;flex:none;filter:drop-shadow(0 6px 14px rgba(0,0,0,.2))}}
header h1{{font-size:46px;font-weight:800;letter-spacing:-1.2px;line-height:1.05}}
header p{{font-size:19px;color:#d4ede7;margin-top:6px}}
main{{flex:1;padding:24px 56px 0;display:flex;flex-direction:column;gap:18px}}
.lab{{font-size:13px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--acc);margin-bottom:10px}}
.ways{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}
.way{{background:#fff;border:1px solid var(--line);border-radius:18px;padding:16px 16px 14px}}
.way .h{{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px}}
.way .wi{{width:40px;height:40px;border-radius:11px;background:var(--acc2);display:grid;place-items:center;flex:none}}
.way p{{font-size:14.5px;line-height:1.4;color:var(--muted);margin-top:8px}}
.badge{{font-size:11px;font-weight:800;letter-spacing:.06em;color:#fff;background:var(--acc);padding:2px 7px;border-radius:5px;margin-left:auto}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:16px;flex:1;min-height:0}}
.col{{background:#fff;border:1px solid var(--line);border-radius:20px;padding:20px 22px;display:flex;flex-direction:column}}
.tip{{margin-top:10px;background:var(--acc2);border-radius:14px;padding:13px 15px;font-size:14px;line-height:1.45;color:var(--acc-d)}} .tip strong{{color:var(--acc-d)}}
.term{{margin-top:10px;background:#0f1d24;border-radius:14px;padding:14px 16px;font-family:'DejaVu Sans Mono',monospace;font-size:12.5px;line-height:1.7;color:#d7f3ec}} .term i{{color:#7fb8aa;font-style:normal}}
.col h2{{font-size:22px;font-weight:800;letter-spacing:-.4px}}
.col .who{{font-size:14.5px;color:var(--muted);margin:2px 0 8px}}
.st{{flex:1 1 auto;display:flex;gap:12px;align-items:center;padding:12px 0;border-top:1px solid var(--line)}}
.n{{flex:none;width:30px;height:30px;border-radius:50%;background:var(--acc);color:#fff;font-weight:800;font-size:15px;display:grid;place-items:center;margin-top:2px}}
.si{{flex:none;width:38px;height:38px;border-radius:10px;background:var(--acc2);display:grid;place-items:center}}
.st .t{{display:block;font-size:19px;font-weight:700;margin-bottom:2px;color:var(--ink)}} .st span{{font-size:15.5px;line-height:1.42;color:var(--muted)}} .st span strong{{color:var(--ink)}}
.st code{{font-size:12.5px;padding:2px 6px}}
footer{{flex:none;margin-top:18px;background:#fff;border-top:1px solid var(--line);padding:16px 56px 22px;display:flex;align-items:center;gap:18px}}
.repo{{font-size:22px;font-weight:800;color:var(--acc)}} .sm{{font-size:13.5px;color:var(--muted);margin-top:2px}}
.warn{{margin-left:auto;background:var(--warm2);color:var(--warm);font-size:13px;font-weight:600;line-height:1.35;padding:9px 13px;border-radius:12px;max-width:360px}}
</style>
<header>{INV}<div><h1 class="disp">Install &amp; use Lullwire Relay</h1><p>Pick how you'll use it, then follow five steps. One person per group runs the relay.</p></div></header>
<main>
 <section><div class="lab">Choose how to use it</div><div class="ways">
  <div class="way"><div class="h"><span class="wi">{ic('android')}</span>Android app<span class="badge">APK</span></div><p>Download from GitHub Releases, check the fingerprint, install. No store needed.</p></div>
  <div class="way"><div class="h"><span class="wi">{ic('install')}</span>Install web app</div><p>Open an invite link, then <b>Install</b> or <b>Add to Home Screen</b>. Android, desktop, iPhone.</p></div>
  <div class="way"><div class="h"><span class="wi">{ic('web')}</span>Any browser</div><p>Just open the invite link. Nothing to install; calls need a recent browser.</p></div>
 </div></section>
 <div class="cols">
  <div class="col"><h2>Use it</h2><div class="who">Everyone you invite</div>
   {step(1,'link','Open your invite','Tap the link or scan the QR code a friend sent you.')}
   {step(2,'user','Pick a name','No phone number, no email. Your key is made on your device.')}
   {step(3,'shield','Check the safety code','Compare it once, in person or on a call, then tap <strong>They match</strong>.')}
   {step(4,'video','Chat and call','Messages, voice and video calls, encrypted end to end.')}
   {step(5,'words','Turn on recovery words','Write down 8 words. They bring your profile back on any device.')}
   <div class="tip"><strong>Tip:</strong> on Android, share an invite link to the Lullwire Relay app, or paste it on the welcome screen. Got a new phone? Choose <strong>From my other device</strong> and scan.</div>
  </div>
  <div class="col"><h2>Host it</h2><div class="who">One person per group</div>
   {step(1,'server','Get the relay','One small program from Releases: Linux, Raspberry Pi, Windows, macOS, or a spare phone.')}
   {step(2,'eye','Run the setup','<code>lullwire-relay init</code> asks a few questions and makes it private: a hidden path and a join code.')}
   {step(3,'lock','Give it HTTPS','It prints the Caddy, Cloudflare Tunnel or Tor setup for you. Tor is optional.')}
   {step(4,'send','Invite people','Open your private address, create a profile, tap <strong>Invite someone</strong>.')}
   {step(5,'shield','Keep it healthy','Keep the device updated and back up its data folder.')}
   <div class="term"><i>$</i> ./lullwire-relay init<br><i>  How will people reach this relay? 1</i><br><i>  Make it private (recommended)? [Y/n]</i><br><i>$</i> ./lullwire-relay</div>
  </div>
 </div>
</main>
<footer><div><div class="repo">github.com/altrudev/Lullwire-Relay</div><div class="sm">Guides: docs/SELF-HOSTING.md · AGPL-3.0 · © 2026 Valentyn Rukhaylo (ALTRU.dev)</div></div>
<div class="warn">Experimental, not yet audited by outside cryptographers. If your safety depends on it, use Signal.</div></footer>"""

JOBS = [('logo-horizontal.png', LOCKUP, 1200, 320, True), ('social-preview.png', SOCIAL, 1280, 640, False),
        ('banner.png', BANNER, 1600, 480, False), ('install-and-use.png', INSTALL, 1080, 1350, False)]
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ.get('CHROME') or None)
    for name, html, w, h, transparent in JOBS:
        pg = b.new_page(viewport={'width': w, 'height': h}, device_scale_factor=2 if h > 320 or not transparent else 2)
        pg.set_content('<!doctype html><meta charset="utf-8">' + html); pg.wait_for_timeout(300)
        over = pg.evaluate('[document.documentElement.scrollWidth, document.documentElement.scrollHeight]')
        if over[0] > w or over[1] > h: print('  overflow', name, over, file=sys.stderr)
        pg.screenshot(path=os.path.join(HERE, name), omit_background=transparent); pg.close()
        print('rendered', name)
    b.close()
