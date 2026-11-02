// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal page-level DevTools client for an Android WebView (which doesn't allow the
// browser-level control Playwright needs): run JS, wait for conditions, tap.
const sleep = ms => new Promise(r => setTimeout(r, ms));
module.exports = async function connect(port) {
  const pages = await (await fetch(`http://localhost:${port}/json`)).json();
  const ws = new WebSocket(pages.find(p => p.type === 'page').webSocketDebuggerUrl);
  await new Promise((ok, bad) => { ws.onopen = ok; ws.onerror = bad; });
  let id = 0; const wait = new Map(), errors = [];
  ws.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.id && wait.has(m.id)) { const w = wait.get(m.id); wait.delete(m.id); m.error ? w.bad(new Error(m.error.message)) : w.ok(m.result); }
    if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') errors.push(m.params.args.map(a => a.value || a.description).join(' '));
    if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') errors.push(m.params.entry.text + ' ' + (m.params.entry.url || ''));
  };
  const send = (method, params = {}) => new Promise((ok, bad) => { const i = ++id; wait.set(i, { ok, bad }); ws.send(JSON.stringify({ id: i, method, params })); });
  await send('Runtime.enable'); await send('Log.enable'); await send('Page.enable');
  const ev = async expr => {
    const r = await send('Runtime.evaluate', { expression: `(async()=>{${expr}})()`, awaitPromise: true, returnByValue: true, userGesture: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  };
  const q = s => JSON.stringify(s);
  const api = {
    errors, send, ev,
    // Each check is capped: an evaluation during a page load can otherwise never answer.
    async waitFor(cond, ms = 15000) {
      const t = Date.now();
      for (;;) {
        if (await Promise.race([ev(`return !!(${cond})`).catch(() => false), sleep(3000).then(() => false)])) return;
        if (Date.now() - t > ms) throw new Error('timeout: ' + cond);
        await sleep(250);
      }
    },
    async waitVisible(s, ms) { return api.waitFor(`(e=>e&&!e.closest('[hidden]')&&e.offsetParent!==null)(document.querySelector(${q(s)}))`, ms); },
    async fill(s, v) { return ev(`const e=document.querySelector(${q(s)}); e.value=${q(v)}; e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true}))`); },
    click: s => ev(`document.querySelector(${q(s)}).click()`),
    // A real tap through the touch screen, so permission prompts see a user gesture.
    async tap(s) {
      const r = await ev(`const e=document.querySelector(${q(s)}); e.scrollIntoView({block:'center'}); const b=e.getBoundingClientRect(); return [b.x+b.width/2, b.y+b.height/2]`);
      await send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x: r[0], y: r[1] }] });
      await send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
      await sleep(150);
    },
    text: s => ev(`return document.querySelector(${q(s)}).textContent`),
    value: s => ev(`return document.querySelector(${q(s)}).value`),
    async load(url) { await send('Page.navigate', { url }).catch(() => {}); await sleep(1000); send('Page.reload').catch(() => {}); await sleep(3000); },
  };
  return api;
};
