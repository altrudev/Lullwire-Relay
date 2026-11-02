'use strict';
// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Signed builds (RELEASE_KEY set): the app runs only from a cache whose every file
// matched release.json, a manifest signed with the release key pinned below. New
// code is fetched in the background and used only if it is signed, newer and
// complete; anything else is refused and reported to the page. Unsigned builds
// (development, or before the maintainer ran keygen): network first, offline fallback.
//
// Limit: browsers always let the server replace this file (sw.js) itself, so a host
// that is fully compromised can still ship new code. Pin an IPFS CID or use the
// Android app when that matters. See SECURITY.md.

const RELEASE_KEY = ''; // set by: go run ./cmd/lullwire-release keygen
const LEGACY = 'lullwire-shell';
const META = 'lullwire-meta';
const SHELL = ['./', 'index.html', 'style.css', 'config.js', 'app.js', 'call.js', 'worklet.js', 'vendor/words.js', 'vendor/qrcode.js', 'manifest.json', 'icon.svg', 'icon-192.png', 'apple-touch-icon.png'];
const CHECK_EVERY = 30 * 60000;

const enc = new TextEncoder();
const b64d = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const hex = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, '0')).join('');
const scopePath = () => new URL(self.registration.scope).pathname;
const fileOf = url => { let p = new URL(url).pathname.slice(scopePath().length); if (p === '' || p.endsWith('/')) p += 'index.html'; return p; };

async function getState() {
  const r = await (await caches.open(META)).match('state');
  return r ? r.json() : {};
}
async function setState(st) { await (await caches.open(META)).put('state', new Response(JSON.stringify(st))); }
const newer = (a, b) => { // is version a newer than b?
  const x = String(a).split('.').map(Number), y = String(b || '0').split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); }
  return false;
};
async function fingerprint() { return hex(await crypto.subtle.digest('SHA-256', b64d(RELEASE_KEY))).slice(0, 16).toUpperCase(); }

// Fetch release.json, check its signature, then fetch and check every file into a new cache.
async function stage() {
  const rel = await (await fetch('release.json', { cache: 'no-store' })).json();
  if (!rel || !rel.m || !rel.s) throw new Error('unsigned');
  const key = await crypto.subtle.importKey('raw', b64d(RELEASE_KEY), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  if (!(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64d(rel.s), enc.encode(rel.m)))) throw new Error('bad signature');
  const m = JSON.parse(rel.m);
  if (m.v !== 1 || m.key !== RELEASE_KEY || !m.files || !m.version) throw new Error('bad manifest');
  const name = 'lullwire-' + m.version + '-' + Date.now();
  const cache = await caches.open(name);
  try {
    await Promise.all(Object.entries(m.files).map(async ([file, sum]) => {
      const res = await fetch(file, { cache: 'no-store' });
      if (!res.ok) throw new Error(file + ': ' + res.status);
      const body = await res.clone().arrayBuffer();
      if (hex(await crypto.subtle.digest('SHA-256', body)) !== sum) throw new Error(file + ' does not match the signed release');
      await cache.put(file, res);
    }));
  } catch (e) { await caches.delete(name); throw e; }
  return { cache: name, version: m.version, files: Object.keys(m.files) };
}

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    if (!RELEASE_KEY) { await (await caches.open(LEGACY)).addAll(SHELL).catch(() => {}); return; }
    const st = await getState();
    if (st.cache && st.key === RELEASE_KEY) return; // already running a verified release
    const s = await stage(); // throws: this worker is not installed, and the app runs from the network
    await setState({ ...s, key: RELEASE_KEY, checked: Date.now(), warn: null });
  })());
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const st = await getState();
    const keep = new Set([META, LEGACY, st.cache, st.next && st.next.cache].filter(Boolean));
    for (const k of await caches.keys()) if (!keep.has(k)) await caches.delete(k);
    await self.clients.claim();
  })());
});

async function tell(msg) { for (const c of await self.clients.matchAll()) c.postMessage(msg); }
let checking = null;
// Look for a newer signed release; stage it for the next start, or report a refusal.
function checkUpdate(force) {
  return checking || (checking = (async () => {
    const st = await getState();
    if (!st.cache || (!force && Date.now() - (st.checked || 0) < CHECK_EVERY)) return;
    st.checked = Date.now();
    try {
      const rel = await (await fetch('release.json', { cache: 'no-store' })).json();
      const m = rel && rel.m ? JSON.parse(rel.m) : null;
      if (m && m.version === st.version && !st.warn) { await setState(st); return; }
      if (m && !newer(m.version, st.version) && m.version !== st.version) throw new Error('an older release (' + m.version + ')');
      const s = await stage();
      if (s.version === st.version) { await caches.delete(s.cache); st.warn = null; await setState(st); return; }
      if (st.next) await caches.delete(st.next.cache);
      st.next = s; st.warn = null;
      await setState(st);
      tell({ t: 'lullwire-update', version: s.version });
    } catch (e) {
      // Network trouble is not a warning; anything the server sends that fails the checks is.
      if (!(e instanceof TypeError)) { st.warn = String(e.message || e); tell({ t: 'lullwire-refused', why: st.warn }); }
      await setState(st);
    }
  })().finally(() => { checking = null; }));
}

self.addEventListener('fetch', e => {
  const req = e.request, u = new URL(req.url);
  if (req.method !== 'GET' || u.origin !== location.origin || /\/(relay(\.php)?|live)$/.test(u.pathname)) return;
  if (!RELEASE_KEY) {
    e.respondWith(fetch(req).then(r => {
      if (r.ok) { const copy = r.clone(); caches.open(LEGACY).then(c => c.put(req, copy)); }
      return r;
    }).catch(() => caches.match(req, { ignoreSearch: true })));
    return;
  }
  e.respondWith((async () => {
    let st = await getState();
    if (req.mode === 'navigate' && st.next) { // a new page load picks up a staged release
      const old = st.cache; st = { ...st, cache: st.next.cache, version: st.next.version, files: st.next.files, next: null };
      await setState(st); caches.delete(old);
    }
    if (req.mode === 'navigate') e.waitUntil(checkUpdate(false));
    const file = fileOf(req.url);
    if (st.cache && st.files && st.files.includes(file)) {
      const hit = await (await caches.open(st.cache)).match(file);
      if (hit) return hit;
    }
    return fetch(req); // not part of the app (e.g. a cover page): nothing to verify
  })());
});

self.addEventListener('message', e => {
  if (!e.data || e.data.q !== 'status') return;
  e.waitUntil((async () => {
    const st = await getState();
    const out = RELEASE_KEY
      ? { t: 'lullwire-status', signed: true, version: st.version, key: await fingerprint(), warn: st.warn || null, next: st.next ? st.next.version : null }
      : { t: 'lullwire-status', signed: false };
    e.source.postMessage(out);
    if (e.data.check) checkUpdate(true);
  })());
});
