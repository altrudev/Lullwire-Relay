// Frozen copy of the Hush Relay 0.5.0 crypto core (web/app.js lines 1-296), used only by
// tests/compat.test.js to check that 0.6 still talks to 0.5 apps. Remove with LEGACY(v2) in 0.8.
'use strict';
// Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
/* Hush Relay v0.3 — end-to-end encrypted 1:1 messenger. Vanilla JS, WebCrypto only.
 *
 * What a relay stores:
 *   ephPub(65) | iv(12) | AES-GCM(K_outer, padded JSON inner)
 *   K_outer = HKDF(ECDH(ephemeral, recipientIdentity))
 *   inner   = { v:2, f: senderIdentityPub, b: senderBox, r: senderRelay, n: senderName,
 *               s: sessionId, h: ratchetHeader, c: ciphertext }
 * The outer layer hides sender and ratchet headers from the relay. Bodies use a
 * Signal-style Double Ratchet (forward secrecy + post-compromise healing).
 * Each session's root secret = HKDF(ECDH(identityA, identityB), sessionId), so
 * only the real holder of the sender's identity key can produce a message that
 * decrypts — that is the sender authentication.
 */

const enc = new TextEncoder(), dec = new TextDecoder();
const ALG = { name: 'ECDH', namedCurve: 'P-256' };
const MAX_SKIP = 200;

const rand = n => crypto.getRandomValues(new Uint8Array(n));
const u8 = b => new Uint8Array(b);
const hex = b => Array.from(u8(b), x => x.toString(16).padStart(2, '0')).join('');
function b64e(buf) {
  const a = u8(buf); let s = '';
  for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64d(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
const sha = async d => hex(await crypto.subtle.digest('SHA-256', typeof d === 'string' ? enc.encode(d) : d));
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}
const isBox = b => typeof b === 'string' && /^[0-9a-f]{32}$/.test(b);
// A relay address must be a plain https URL (http only for local testing), short, with no credentials.
function isRelay(r) {
  if (typeof r !== 'string' || r.length > 256 || /[\s"'<>\\]/.test(r)) return false;
  let u; try { u = new URL(r); } catch { return false; }
  if (u.username || u.password || u.hash || u.search) return false;
  if (u.protocol === 'https:') return true;
  // Tor onion services (v3) are reached over http://, but Tor itself encrypts and
  // authenticates the connection end to end, so they count as secure.
  if (u.protocol === 'http:' && /^[a-z2-7]{56}\.onion$/.test(u.hostname)) return true;
  // Plain-http relays on this machine only, for development: the app itself on localhost,
  // or a debug build of the Android app (a release build never allows this).
  const localApp = typeof location === 'undefined' || /^(localhost|127\.0\.0\.1)$/.test(location.hostname) ||
    (typeof navigator !== 'undefined' && / HushRelayAndroid\/\S+ debug/.test(navigator.userAgent));
  return u.protocol === 'http:' && /^(localhost|127\.0\.0\.1)$/.test(u.hostname) && localApp;
}
const MAX_CLOCK_SKEW = 10 * 60000;

// ---------- primitives ----------
const importPub = raw => crypto.subtle.importKey('raw', typeof raw === 'string' ? b64d(raw) : raw, ALG, true, []);
const dh = async (priv, pubB64) => u8(await crypto.subtle.deriveBits({ name: 'ECDH', public: await importPub(pubB64) }, priv, 256));
async function hkdf(ikm, salt, info, bytes) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return u8(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('hush/v2/' + info) }, k, bytes * 8));
}
async function hmac(key, byte) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return u8(await crypto.subtle.sign('HMAC', k, new Uint8Array([byte])));
}
const aesKey = (raw, use) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [use]);
async function aesEnc(raw, pt, ad) {
  const iv = rand(12);
  return concat(iv, u8(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ad }, await aesKey(raw, 'encrypt'), pt)));
}
async function aesDec(raw, data, ad) {
  return u8(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12), additionalData: ad }, await aesKey(raw, 'decrypt'), data.slice(12)));
}
async function genKP() {
  const kp = await crypto.subtle.generateKey(ALG, false, ['deriveBits']);
  return { priv: kp.privateKey, pub: b64e(await crypto.subtle.exportKey('raw', kp.publicKey)) };
}
// Pad to fixed buckets so the relay learns only a coarse size class.
function pad(str) {
  const b = enc.encode(str);
  const L = [1024, 4096, 16384, 32768].find(x => x >= b.length) || b.length;
  const out = new Uint8Array(L).fill(0x20); out.set(b); return out; // trailing spaces are valid JSON
}

// ---------- identity ----------
async function newIdentity(name, relay) {
  const kp = await crypto.subtle.generateKey(ALG, true, ['deriveBits']); // extractable only so it can go into an encrypted backup
  const pub = b64e(await crypto.subtle.exportKey('raw', kp.publicKey));
  const secret = hex(rand(32));
  const box = (await sha(secret)).slice(0, 32);
  return { priv: kp.privateKey, pub, secret, box, name, relay };
}
const contactId = async pubB64 => (await sha(b64d(pubB64))).slice(0, 32);
async function safetyNumber(pubA, pubB) {
  const [x, y] = [pubA, pubB].sort();
  return (await sha(concat(b64d(x), b64d(y)))).slice(0, 40).match(/.{5}/g).join(' ');
}

// ---------- Double Ratchet ----------
async function kdfRK(rk, dhOut) { const o = await hkdf(dhOut, rk, 'rk', 64); return [o.slice(0, 32), o.slice(32)]; }
async function kdfCK(ck) { return [await hmac(ck, 2), await hmac(ck, 1)]; } // [next chain key, message key]
async function rootSecret(me, peerPub, sid) { return hkdf(await dh(me.priv, peerPub), b64d(sid), 'root', 32); }

async function initInitiator(me, peerPub) {
  const sid = b64e(rand(16));
  const DHs = await genKP();
  const [RK, CKs] = await kdfRK(await rootSecret(me, peerPub, sid), await dh(DHs.priv, peerPub));
  return { sid, DHs, DHr: peerPub, RK, CKs, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: {}, ts: Date.now() };
}
async function initResponder(me, peerPub, sid) {
  return { sid, DHs: { priv: me.priv, pub: me.pub }, DHr: null, RK: await rootSecret(me, peerPub, sid),
    CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: {}, ts: Date.now() };
}
async function ratchetEncrypt(st, pt, ad) {
  const [ck, mk] = await kdfCK(st.CKs); st.CKs = ck;
  const h = { dh: st.DHs.pub, pn: st.PN, n: st.Ns }; st.Ns++;
  return { h, c: await aesEnc(mk, pt, concat(ad, enc.encode(JSON.stringify(h)))) };
}
async function skipKeys(st, until) {
  if (!st.CKr) return;
  if (until - st.Nr > MAX_SKIP) throw new Error('too many skipped messages');
  while (st.Nr < until) {
    const [ck, mk] = await kdfCK(st.CKr); st.CKr = ck;
    st.skipped[st.DHr + ':' + st.Nr] = mk; st.Nr++;
  }
  const keys = Object.keys(st.skipped);
  for (const k of keys.slice(0, Math.max(0, keys.length - 500))) delete st.skipped[k];
}
// Works on a copy; the caller commits the returned state only if decryption succeeded.
async function ratchetDecrypt(st0, h, c, ad) {
  const st = { ...st0, skipped: { ...st0.skipped } };
  const fullAd = concat(ad, enc.encode(JSON.stringify({ dh: h.dh, pn: h.pn, n: h.n })));
  const sk = h.dh + ':' + h.n;
  if (st.skipped[sk]) { const mk = st.skipped[sk]; delete st.skipped[sk]; return [st, await aesDec(mk, c, fullAd)]; }
  if (h.dh !== st.DHr) {
    await skipKeys(st, h.pn);
    st.PN = st.Ns; st.Ns = 0; st.Nr = 0; st.DHr = h.dh;
    [st.RK, st.CKr] = await kdfRK(st.RK, await dh(st.DHs.priv, st.DHr));
    st.DHs = await genKP();
    [st.RK, st.CKs] = await kdfRK(st.RK, await dh(st.DHs.priv, st.DHr));
  }
  await skipKeys(st, h.n);
  const [ck, mk] = await kdfCK(st.CKr); st.CKr = ck; st.Nr++;
  return [st, await aesDec(mk, c, fullAd)];
}

// ---------- envelope ----------
async function sealOuter(obj, toPub) {
  const eph = await genKP(), ephRaw = b64d(eph.pub);
  const key = await hkdf(await dh(eph.priv, toPub), new Uint8Array(32), 'outer', 32);
  return concat(ephRaw, await aesEnc(key, pad(JSON.stringify(obj)), ephRaw));
}
async function openOuter(me, bytes) {
  const ephRaw = bytes.slice(0, 65);
  const key = await hkdf(await dh(me.priv, b64e(ephRaw)), new Uint8Array(32), 'outer', 32);
  return JSON.parse(dec.decode(await aesDec(key, bytes.slice(65), ephRaw)));
}

// c = contact object { pub, sessions:{}, active }. Mutates c.sessions; caller persists c.
async function encryptFor(me, c, msg) {
  let st = c.active && c.sessions[c.active];
  if (!st || !st.CKs) {
    st = await initInitiator(me, c.pub);
    st.mine = true;
    c.sessions[st.sid] = st; c.active = st.sid;
    c.usedSids = [...(c.usedSids || []), st.sid].slice(-300);
  }
  const { h, c: ct } = await ratchetEncrypt(st, enc.encode(JSON.stringify(msg)), enc.encode(me.pub + '|' + c.pub));
  st.ts = Date.now();
  return sealOuter({ v: 2, f: me.pub, b: me.box, r: me.relay, n: me.name, s: st.sid, h, c: b64e(ct) }, c.pub);
}
async function decryptFrom(me, c, inner) {
  const h = inner.h;
  if (!h || typeof h.dh !== 'string' || !Number.isInteger(h.n) || !Number.isInteger(h.pn) || h.n < 0 || h.pn < 0 ||
      typeof inner.s !== 'string' || typeof inner.c !== 'string') throw new Error('bad header');
  const isNew = !c.sessions[inner.s];
  // A session id is only ever started once: a relay replaying an old opening message is refused.
  if (isNew && (c.usedSids || []).includes(inner.s)) throw new Error('replayed session');
  const st = c.sessions[inner.s] || await initResponder(me, c.pub, inner.s);
  const [ns, pt] = await ratchetDecrypt(st, h, b64d(inner.c), enc.encode(c.pub + '|' + me.pub));
  const msg = JSON.parse(dec.decode(pt));
  if (typeof msg !== 'object' || msg === null || !Number.isFinite(msg.ts)) throw new Error('bad message');
  // Opening messages from before this copy of the account existed are replays.
  if (isNew && msg.ts < (c.floor || 0) - MAX_CLOCK_SKEW) throw new Error('stale session');
  // Commit only now that the message is authentic and fresh.
  const cur = c.active && c.sessions[c.active];
  ns.ts = Date.now(); ns.got = true;
  c.sessions[inner.s] = ns;
  c.opened = null;
  if (isNew) {
    c.usedSids = [...(c.usedSids || []), inner.s].slice(-300);
    c.opened = inner.s; // the UI acts on resets only for freshly opened sessions
    // A freshly opened session from the peer becomes the one we answer on. The single exception keeps
    // two people who both started a session at the same moment from swapping forever: if our own
    // session has not been answered yet, both sides keep whichever session id sorts first.
    const tie = cur && cur.mine && !cur.got;
    c.active = tie && c.active < inner.s ? c.active : inner.s;
  } else if (!cur) c.active = inner.s;
  c.lastTs = Math.max(c.lastTs || 0, Math.min(msg.ts, Date.now() + MAX_CLOCK_SKEW));
  const ids = Object.keys(c.sessions).sort((a, b) => c.sessions[b].ts - c.sessions[a].ts);
  for (const id of ids.slice(4)) if (id !== c.active) delete c.sessions[id];
  return msg;
}

// ---------- account bundles (identity + contact list, never ratchet state) ----------
const BACKUP_CONTACTS = 900; // contacts that fit in a recovery slot or move bundle, even with long relay addresses
async function backupData(me, contacts) {
  return {
    v: 3,
    me: { jwk: await crypto.subtle.exportKey('jwk', me.priv), pub: me.pub, secret: me.secret, box: me.box,
          name: me.name, relay: me.relay, rec: me.rec || null, join: me.join || null, inviteTok: me.inviteTok || null },
    at: Date.now(),
    // Unanswered message requests are left out, so strangers cannot bloat the backup.
    // If there are more contacts than fit, verified and recently active ones come first.
    contacts: contacts.filter(c => !c.request)
      .sort((a, b) => (!!a.blocked - !!b.blocked) || (!!b.verified - !!a.verified) || ((b.ts || 0) - (a.ts || 0)))
      .slice(0, BACKUP_CONTACTS)
      .map(c => ({ pub: c.pub, box: c.box, relay: c.relay, name: c.name, verified: !!c.verified, blocked: !!c.blocked }))
  };
}
async function restoreData(data) {
  if (!data || !data.me || !data.me.jwk) throw new Error('not a Hush account');
  const { jwk, ...rest } = data.me;
  const priv = await crypto.subtle.importKey('jwk', jwk, ALG, true, ['deriveBits']);
  // Prove the private key matches the claimed public key before trusting the bundle.
  const probe = await genKP();
  const a = await dh(priv, probe.pub), b = await dh(probe.priv, rest.pub);
  if (hex(a) !== hex(b)) throw new Error('key mismatch');
  if (typeof rest.secret !== 'string' || !/^[0-9a-f]{64}$/.test(rest.secret) || (await sha(rest.secret)).slice(0, 32) !== rest.box)
    throw new Error('mailbox mismatch');
  if (!isRelay(rest.relay)) throw new Error('bad relay address');
  rest.name = String(rest.name || '').slice(0, 40);
  return { me: { ...rest, priv }, contacts: Array.isArray(data.contacts) ? data.contacts.slice(0, 1000) : [], at: Number(data.at) || Date.now() };
}

// Passphrase-protected backup file
async function passKey(pass, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  return u8(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, k, 256));
}
async function exportBackup(me, contacts, pass) {
  const salt = rand(16);
  const data = await backupData(me, contacts);
  return 'HUSH3.' + b64e(salt) + '.' + b64e(await aesEnc(await passKey(pass, salt), enc.encode(JSON.stringify(data)), enc.encode('hush-backup')));
}
async function importBackup(text, pass) {
  const [tag, s, d] = String(text).trim().split('.');
  if (!/^HUSH[23]$/.test(tag) || !s || !d) throw new Error('not a Hush backup');
  return restoreData(JSON.parse(dec.decode(await aesDec(await passKey(pass, b64d(s)), b64d(d), enc.encode('hush-backup')))));
}

// Recovery words: 6 random BIP39 words = 66 bits. PBKDF2 turns them into
// a slot locator, a write token and an encryption key. The relay sees only the
// locator and sha256(token), so even its host cannot open or replace the backup.
const WORDS = typeof module !== 'undefined' ? require('../../web/vendor/words.js') : self.HUSH_WORDS;
function genWords() {
  return Array.from(crypto.getRandomValues(new Uint16Array(6)), n => WORDS[n & 2047]).join(' ');
}
function normWords(text) {
  const parts = String(text).toLowerCase().split(/[^a-z]+/).filter(Boolean);
  if (parts.length !== 6) throw new Error('Enter exactly 6 words');
  return parts.map(p => {
    if (WORDS.includes(p)) return p;
    const m = p.length >= 4 ? WORDS.filter(w => w.startsWith(p.slice(0, 4))) : [];
    if (m.length === 1) return m[0];
    throw new Error('"' + p + '" is not one of the recovery words');
  }).join(' ');
}
async function recoveryKeys(words) {
  const k = await crypto.subtle.importKey('raw', enc.encode(normWords(words)), 'PBKDF2', false, ['deriveBits']);
  const o = u8(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode('hush/recovery/v1'), iterations: 600000 }, k, 640));
  return { l: hex(o.slice(0, 16)), t: hex(o.slice(16, 48)), k: b64e(o.slice(48, 80)) };
}
async function sealRecovery(rec, data) {
  return b64e(await aesEnc(b64d(rec.k), enc.encode(JSON.stringify(data)), enc.encode('hush-recovery:' + rec.l)));
}
async function openRecovery(rec, d) {
  return JSON.parse(dec.decode(await aesDec(b64d(rec.k), b64d(d), enc.encode('hush-recovery:' + rec.l)))); // raw bundle; adopt() verifies it
}

// Short code shown on both devices during linking, so a swapped QR is noticed.
async function linkCode(pub) {
  // 12 digits (~40 bits): grinding a matching key inside the 10-minute window is impractical.
  const h = await sha(b64d(pub));
  return String(BigInt('0x' + h.slice(0, 16)) % 1000000000000n).padStart(12, '0').replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3');
}

if (typeof module !== 'undefined') module.exports = {
  newIdentity, encryptFor, decryptFrom, sealOuter, openOuter, genKP, safetyNumber, contactId,
  BACKUP_CONTACTS, backupData, restoreData, exportBackup, importBackup, genWords, normWords, recoveryKeys, sealRecovery, openRecovery,
  linkCode, isRelay, b64e, b64d, hex, rand, sha
};
