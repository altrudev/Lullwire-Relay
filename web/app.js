'use strict';
// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
/* Lullwire Relay v0.6 — end-to-end encrypted 1:1 messenger. Vanilla JS, WebCrypto only.
 * docs/PROTOCOL.md is the full specification; in short:
 *
 * What a relay stores:
 *   ephPub(65) | iv(12) | AES-GCM(K_outer, padded JSON inner)
 *   K_outer = HKDF(ECDH(ephemeral, recipient's signed prekey, or identity key))
 *   inner   = { v:4, f: senderIdentityPub, b: senderBox, r: senderRelay, n: senderName,
 *               q: signed address card, s: sessionId, h: ratchetHeader, c: ciphertext }
 * Sessions open X3DH-style against the recipient's signed prekey, then run a
 * Signal-style Double Ratchet (forward secrecy + post-compromise healing). The
 * sender's mailbox, relay, name and card are bound into every message's
 * authenticated data. The identity key both agrees (ECDH) and signs (ECDSA), the
 * way Signal's XEdDSA reuses its identity key: it signs the prekey and address.
 */

const enc = new TextEncoder(), dec = new TextDecoder();
const ALG = { name: 'ECDH', namedCurve: 'P-256' };
const SIG = { name: 'ECDSA', namedCurve: 'P-256' }, SIGH = { name: 'ECDSA', hash: 'SHA-256' };
const MAX_SKIP = 200;
const DAY = 864e5;
// Signed prekeys: a new one every 14 days. Senders use a prekey for at most 28 days
// after it was made; mail can wait on a relay for 14 more, so each is kept 45 days.
const SPK_ROTATE = 14 * DAY, SPK_USE = 28 * DAY, SPK_KEEP = 45 * DAY;

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
  if (typeof r !== 'string' || r.length > 256 || /[\s"'<>\\|]/.test(r)) return false;
  let u; try { u = new URL(r); } catch { return false; }
  if (u.username || u.password || u.hash || u.search) return false;
  if (u.protocol === 'https:') return true;
  // Tor onion services (v3) are reached over http://, but Tor itself encrypts and
  // authenticates the connection end to end, so they count as secure.
  if (u.protocol === 'http:' && /^[a-z2-7]{56}\.onion$/.test(u.hostname)) return true;
  // Plain-http relays on this machine only, for development: the app itself on localhost,
  // or a debug build of the Android app (a release build never allows this).
  const localApp = typeof location === 'undefined' || /^(localhost|127\.0\.0\.1)$/.test(location.hostname) ||
    (typeof navigator !== 'undefined' && / LullwireAndroid\/\S+ debug/.test(navigator.userAgent));
  return u.protocol === 'http:' && /^(localhost|127\.0\.0\.1)$/.test(u.hostname) && localApp;
}
const MAX_CLOCK_SKEW = 10 * 60000;

// ---------- primitives ----------
const importPub = raw => crypto.subtle.importKey('raw', typeof raw === 'string' ? b64d(raw) : raw, ALG, true, []);
const importVerify = raw => crypto.subtle.importKey('raw', typeof raw === 'string' ? b64d(raw) : raw, SIG, false, ['verify']);
const dh = async (priv, pubB64) => u8(await crypto.subtle.deriveBits({ name: 'ECDH', public: await importPub(pubB64) }, priv, 256));
// hkdf: the v2 labels ("hush/v2/" + info). hkdfX: the full label is given.
const hkdf = (ikm, salt, info, bytes) => hkdfX(ikm, salt, 'hush/v2/' + info, bytes);
async function hkdfX(ikm, salt, info, bytes) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return u8(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, k, bytes * 8));
}
async function hmac(key, byte) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return u8(await crypto.subtle.sign('HMAC', k, new Uint8Array([byte])));
}
const aesKey = (raw, use) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [use]);
async function aesEncK(key, pt, ad) {
  const iv = rand(12);
  return concat(iv, u8(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ad }, key, pt)));
}
async function aesDecK(key, data, ad) {
  return u8(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12), additionalData: ad }, key, data.slice(12)));
}
const aesEnc = async (raw, pt, ad) => aesEncK(await aesKey(raw, 'encrypt'), pt, ad);
const aesDec = async (raw, data, ad) => aesDecK(await aesKey(raw, 'decrypt'), data, ad);
// Ratchet and envelope keys. Extractable only so the vault can store them encrypted.
async function genKP() {
  const kp = await crypto.subtle.generateKey(ALG, true, ['deriveBits']);
  return { priv: kp.privateKey, pub: b64e(await crypto.subtle.exportKey('raw', kp.publicKey)) };
}
// Pad to fixed buckets so the relay and the network learn only a coarse size class.
// A random tail (up to 1/8 of the bucket) keeps sizes from being an exact fingerprint;
// payloads above 32 KiB (a profile being moved) are padded to a multiple of 16 KiB.
const randInt = n => crypto.getRandomValues(new Uint32Array(1))[0] % n;
function pad(str) {
  const b = enc.encode(str);
  const B = [1024, 4096, 16384, 32768].find(x => x >= b.length);
  const L = B ? B + randInt(B >> 3) : Math.ceil(b.length / 16384) * 16384;
  const out = new Uint8Array(L).fill(0x20); out.set(b); return out; // trailing spaces are valid JSON
}

// ---------- identity ----------
// One P-256 key pair is the identity. Its private JWK lives only in the encrypted
// vault; at runtime it is held as two non-extractable keys: one for ECDH, one for ECDSA.
async function keysFromJwk(jwk) {
  const j = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d };
  const [priv, sign] = await Promise.all([
    crypto.subtle.importKey('jwk', j, ALG, false, ['deriveBits']),
    crypto.subtle.importKey('jwk', j, SIG, false, ['sign'])]);
  return { priv, sign };
}
async function newIdentity(name, relay) {
  const kp = await crypto.subtle.generateKey(ALG, true, ['deriveBits']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const pub = b64e(await crypto.subtle.exportKey('raw', kp.publicKey));
  const secret = hex(rand(32));
  const box = (await sha(secret)).slice(0, 32);
  const me = { ...(await keysFromJwk(jwk)), jwk, pub, secret, box, name, relay, spks: [] };
  await rotatePrekeys(me);
  return me;
}
const contactId = async pubB64 => (await sha(b64d(pubB64))).slice(0, 32);
async function safetyNumber(pubA, pubB) {
  const [x, y] = [pubA, pubB].sort();
  return (await sha(concat(b64d(x), b64d(y)))).slice(0, 40).match(/.{5}/g).join(' ');
}

// ---------- signed prekeys and address cards ----------
async function newPrekey(now) {
  const kp = await crypto.subtle.generateKey(ALG, true, ['deriveBits']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { pub: b64e(await crypto.subtle.exportKey('raw', kp.publicKey)), t: now, jwk, priv: await prekeyPriv(jwk) };
}
const prekeyPriv = jwk => crypto.subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }, ALG, false, ['deriveBits']);
// Makes a new prekey when the newest is 14 days old and forgets those older than 45 days.
// Returns true when anything changed (the caller saves `me`).
async function rotatePrekeys(me, now = Date.now()) {
  me.spks = (me.spks || []).filter(k => now - k.t < SPK_KEEP);
  const before = me.spks.length && me.spks[0].pub;
  if (!me.spks.length || now - me.spks[0].t >= SPK_ROTATE || me.spks[0].t > now + DAY) me.spks.unshift(await newPrekey(now));
  if (me.spks.length && me.spks[0].pub !== before) { me.card = null; return true; }
  return false;
}
// An address card says "my mailbox, my relay and my current prekey", signed by the
// identity key. It travels in invites and in every message, so contacts can open
// sessions with forward secrecy and follow a mailbox move without trusting the relay.
const cardMsg = (pub, b, r, s, t) => enc.encode('lullwire/v4/card|' + pub + '|' + b + '|' + r + '|' + s + '|' + t);
async function makeCard(me) {
  const k = me.spks && me.spks[0];
  if (!k) return null;
  const tag = me.box + '|' + me.relay + '|' + k.pub;
  if (me.card && me.card.tag === tag) return me.card.q;
  const g = b64e(await crypto.subtle.sign(SIGH, me.sign, cardMsg(me.pub, me.box, me.relay, k.pub, k.t)));
  me.card = { tag, q: { s: k.pub, t: k.t, g } };
  return me.card.q;
}
async function checkCard(pub, b, r, q, now = Date.now()) {
  if (!q || typeof q !== 'object' || typeof q.s !== 'string' || typeof q.g !== 'string' || q.s.length > 100 || q.g.length > 100 ||
      !Number.isSafeInteger(q.t) || q.t <= 0 || q.t > now + DAY || !isBox(b) || !isRelay(r)) return false;
  try {
    await importPub(q.s);
    return await crypto.subtle.verify(SIGH, await importVerify(pub), b64d(q.g), cardMsg(pub, b, r, q.s, q.t));
  } catch { return false; }
}
// A contact's prekey is used only while it is fresh enough that they still hold it.
const usablePrekey = (c, now = Date.now()) => c.card && c.v4 && now - c.card.t < SPK_USE ? c.card.s : null;
// Accept a verified card if it is newer than the one we have. Returns true if it was taken.
async function takeCard(c, b, r, q) {
  if (!q || (c.card && q.t <= c.card.t) || !(await checkCard(c.pub, b, r, q))) return false;
  c.card = { s: q.s, t: q.t, g: q.g, b, r }; c.v4 = true;
  return true;
}

// ---------- Double Ratchet ----------
async function kdfRK(rk, dhOut) { const o = await hkdf(dhOut, rk, 'rk', 64); return [o.slice(0, 32), o.slice(32)]; }
async function kdfCK(ck) { return [await hmac(ck, 2), await hmac(ck, 1)]; } // [next chain key, message key]
async function rootSecret(me, peerPub, sid) { return hkdf(await dh(me.priv, peerPub), b64d(sid), 'root', 32); }

// X3DH-style opening against the peer's signed prekey (no one-time prekeys):
//   SK = HKDF(DH(IKa, SPKb) ‖ DH(EKa, IKb) ‖ DH(EKa, SPKb), salt = sessionId)
// Once SPKb is deleted, a stolen identity key can't read recorded opening messages.
async function initInitiator4(me, peerPub, spk) {
  const sid = b64e(rand(16)), EK = await genKP();
  const SK = await hkdfX(concat(await dh(me.priv, spk), await dh(EK.priv, peerPub), await dh(EK.priv, spk)), b64d(sid), 'lullwire/v4/x3dh', 32);
  const DHs = await genKP();
  const [RK, CKs] = await kdfRK(SK, await dh(DHs.priv, spk));
  return { sid, DHs, DHr: spk, RK, CKs, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: {}, ts: Date.now(), x: { e: EK.pub, sp: spk } };
}
async function initResponder4(me, peerPub, sid, e, sp) {
  const k = (me.spks || []).find(x => x.pub === sp);
  if (!k) throw new Error('unknown prekey');
  const SK = await hkdfX(concat(await dh(k.priv, peerPub), await dh(me.priv, e), await dh(k.priv, e)), b64d(sid), 'lullwire/v4/x3dh', 32);
  return { sid, DHs: { priv: k.priv, pub: k.pub }, DHr: null, RK: SK, CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: {}, ts: Date.now() };
}
// LEGACY(v2): sessions rooted in the two identity keys only, for contacts whose app
// has no prekey yet (0.5 and earlier) or whose prekey we don't know. Remove in 0.8.
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
// The header is authenticated in a fixed shape. Opening messages also carry the
// ephemeral key and the prekey they used, until the peer has answered.
const hdrBytes = h => enc.encode(JSON.stringify(h.e !== undefined ? { dh: h.dh, pn: h.pn, n: h.n, e: h.e, sp: h.sp } : { dh: h.dh, pn: h.pn, n: h.n }));
async function ratchetEncrypt(st, pt, ad) {
  const [ck, mk] = await kdfCK(st.CKs); st.CKs = ck;
  const h = { dh: st.DHs.pub, pn: st.PN, n: st.Ns }; st.Ns++;
  if (st.x && !st.got) { h.e = st.x.e; h.sp = st.x.sp; }
  return { h, c: await aesEnc(mk, pt, concat(ad, hdrBytes(h))) };
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
  const fullAd = concat(ad, hdrBytes(h));
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
// The outer layer is sealed to one of our prekeys (newest first) or, for senders
// without a fresh prekey of ours, to the identity key. We try each in turn.
async function openOuter(me, bytes) {
  const ephRaw = bytes.slice(0, 65), eph = b64e(ephRaw), body = bytes.slice(65);
  const keys = [...(me.spks || []).map(k => k.priv), me.priv];
  for (const priv of keys) {
    let pt;
    try { pt = await aesDec(await hkdf(await dh(priv, eph), new Uint8Array(32), 'outer', 32), body, ephRaw); } catch { continue; }
    return JSON.parse(dec.decode(pt));
  }
  throw new Error('not for this account');
}
// What the ratchet authenticates besides the header: both identities, and (v4) the
// sender's mailbox, relay, name and card, so nothing in the envelope is unbound.
function innerAd(v, from, to, inner) {
  const ids = enc.encode(from + '|' + to);
  if (v !== 4) return ids; // LEGACY(v2)
  const q = inner.q ? [inner.q.s, inner.q.t, inner.q.g] : null;
  return concat(ids, enc.encode('|' + JSON.stringify([inner.b, inner.r, inner.n, q, inner.qa === undefined ? null : inner.qa])));
}

// c = contact object { pub, sessions:{}, active, card?, v4? }. Mutates c; caller persists c.
// Returns the sealed envelope (to the contact's fresh prekey if we have one, else their identity key).
async function encryptFor(me, c, msg) {
  const now = Date.now();
  let st = c.active && c.sessions[c.active];
  if (!st || !st.CKs) {
    const spk = usablePrekey(c, now);
    st = spk ? await initInitiator4(me, c.pub, spk) : await initInitiator(me, c.pub);
    st.mine = true;
    c.sessions[st.sid] = st; c.active = st.sid;
    c.usedSids = [...(c.usedSids || []), st.sid].slice(-300);
  }
  // Contacts whose app sent us a card speak v4; to others we send v2 with the card
  // attached (they ignore it), so they learn ours when they update. Our card rides
  // along until the contact confirms (qa) that they hold it; we confirm theirs.
  const v = c.v4 ? 4 : 2;
  const inner = { v, f: me.pub, b: me.box, r: me.relay, n: me.name, s: st.sid };
  const q = await makeCard(me); if (q && c.qAck !== q.t) inner.q = q;
  if (v === 4 && c.card) inner.qa = c.card.t;
  const { h, c: ct } = await ratchetEncrypt(st, enc.encode(JSON.stringify(msg)), innerAd(v, me.pub, c.pub, inner));
  inner.h = h; inner.c = b64e(ct);
  st.ts = now;
  return sealOuter(inner, usablePrekey(c, now) || c.pub);
}
async function decryptFrom(me, c, inner) {
  const h = inner.h;
  if (!h || typeof h.dh !== 'string' || !Number.isInteger(h.n) || !Number.isInteger(h.pn) || h.n < 0 || h.pn < 0 ||
      typeof inner.s !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(inner.s) || typeof inner.c !== 'string' || (inner.v !== 2 && inner.v !== 4) ||
      (h.e !== undefined && (typeof h.e !== 'string' || typeof h.sp !== 'string'))) throw new Error('bad header');
  const isNew = !c.sessions[inner.s];
  // A session id is only ever started once: a relay replaying an old opening message is refused.
  if (isNew && (c.usedSids || []).includes(inner.s)) throw new Error('replayed session');
  const st = c.sessions[inner.s] ||
    (h.e !== undefined ? await initResponder4(me, c.pub, inner.s, h.e, h.sp) : await initResponder(me, c.pub, inner.s));
  const [ns, pt] = await ratchetDecrypt(st, h, b64d(inner.c), innerAd(inner.v, c.pub, me.pub, inner));
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
  if (inner.v === 4) c.v4 = true;
  // Which of our cards they hold. A contact that doesn't say (an older app, or a fresh
  // copy after a restore) gets our card again with the next message.
  c.qAck = inner.v === 4 && Number.isSafeInteger(inner.qa) ? inner.qa : undefined;
  const ids = Object.keys(c.sessions).sort((a, b) => c.sessions[b].ts - c.sessions[a].ts);
  for (const id of ids.slice(4)) if (id !== c.active) delete c.sessions[id];
  return msg;
}

// ---------- account bundles (identity + contact list; never ratchet state, prekeys or cards) ----------
const BACKUP_CONTACTS = 900; // contacts that fit in a recovery slot or move bundle, even with long relay addresses
// `me.jwk` must be supplied by the caller: the app keeps it only in the vault.
async function backupData(me, contacts) {
  if (!me.jwk) throw new Error('identity key not available');
  const { kty, crv, x, y, d } = me.jwk;
  return {
    v: 3,
    me: { jwk: { kty, crv, x, y, d }, pub: me.pub, secret: me.secret, box: me.box,
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
  if (!data || !data.me || !data.me.jwk || typeof data.me.jwk !== 'object') throw new Error('not a Lullwire account');
  const { jwk, ...rest } = data.me;
  const keys = await keysFromJwk(jwk);
  // Prove the private key matches the claimed public key before trusting the bundle.
  const probe = await genKP();
  const a = await dh(keys.priv, probe.pub), b = await dh(probe.priv, rest.pub);
  if (hex(a) !== hex(b)) throw new Error('key mismatch');
  if (typeof rest.secret !== 'string' || !/^[0-9a-f]{64}$/.test(rest.secret) || (await sha(rest.secret)).slice(0, 32) !== rest.box)
    throw new Error('mailbox mismatch');
  if (!isRelay(rest.relay)) throw new Error('bad relay address');
  rest.name = String(rest.name || '').slice(0, 40);
  const { kty, crv, x, y, d } = jwk;
  const me = { ...rest, ...keys, jwk: { kty, crv, x, y, d }, spks: [] };
  await rotatePrekeys(me);
  return { me, contacts: Array.isArray(data.contacts) ? data.contacts.slice(0, 1000) : [], at: Number(data.at) || Date.now() };
}

// Passphrase-protected backup file
async function passKey(pass, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  return u8(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, k, 256));
}
async function exportBackup(me, contacts, pass) {
  const salt = rand(16);
  const data = await backupData(me, contacts);
  return 'LULLWIRE1.' + b64e(salt) + '.' + b64e(await aesEnc(await passKey(pass, salt), enc.encode(JSON.stringify(data)), enc.encode('lullwire/backup')));
}
// LEGACY: HUSH2/HUSH3 files are backups made by Hush Relay 0.5 and earlier.
async function openBackup(text, pass) {
  const [tag, s, d] = String(text).trim().split('.');
  const ad = tag === 'LULLWIRE1' ? 'lullwire/backup' : /^HUSH[23]$/.test(tag) ? 'hush-backup' : null;
  if (!ad || !s || !d) throw new Error('not a Lullwire backup');
  return JSON.parse(dec.decode(await aesDec(await passKey(pass, b64d(s)), b64d(d), enc.encode(ad))));
}
const importBackup = async (text, pass) => restoreData(await openBackup(text, pass));

// Recovery words. New: 8 random BIP39 words = 88 bits ("v2"). LEGACY(v1): 6 words
// (66 bits) are still accepted for recovering and keep syncing until replaced.
// PBKDF2 turns the words into a slot locator, a write token and an encryption key.
// The relay sees only the locator and sha256(token), so even its host cannot open or replace the backup.
const WORDS = typeof module !== 'undefined' ? require('./vendor/words.js') : self.LULLWIRE_WORDS;
const REC_WORDS = 8;
function genWords(n = REC_WORDS) {
  return Array.from(crypto.getRandomValues(new Uint16Array(n)), x => WORDS[x & 2047]).join(' ');
}
function normWords(text) {
  const parts = String(text).toLowerCase().split(/[^a-z]+/).filter(Boolean);
  if (parts.length !== 8 && parts.length !== 6) throw new Error('Enter all ' + REC_WORDS + ' recovery words');
  return parts.map(p => {
    if (WORDS.includes(p)) return p;
    const m = p.length >= 4 ? WORDS.filter(w => w.startsWith(p.slice(0, 4))) : [];
    if (m.length === 1) return m[0];
    throw new Error('"' + p + '" is not one of the recovery words');
  }).join(' ');
}
async function recoveryKeys(words) {
  const w = normWords(words), v = w.split(' ').length === 8 ? 2 : 1;
  const k = await crypto.subtle.importKey('raw', enc.encode(w), 'PBKDF2', false, ['deriveBits']);
  // LEGACY(v1): 6-word slots keep the labels Hush Relay 0.5 used.
  const salt = v === 2 ? 'lullwire/recovery/v2' : 'hush/recovery/v1';
  const o = u8(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 600000 }, k, 640));
  return { v, l: hex(o.slice(0, 16)), t: hex(o.slice(16, 48)), k: b64e(o.slice(48, 80)) };
}
// The slot is padded to a multiple of 16 KiB, so its size says little about the contact list.
async function sealRecovery(rec, data) {
  const json = enc.encode(JSON.stringify(data));
  const pt = new Uint8Array(Math.ceil((json.length + 1) / 16384) * 16384).fill(0x20); pt.set(json);
  return b64e(await aesEnc(b64d(rec.k), pt, recAd(rec)));
}
const recAd = rec => enc.encode((rec.v === 2 ? 'lullwire/recovery:' : 'hush-recovery:') + rec.l);
async function openRecovery(rec, d) {
  return JSON.parse(dec.decode(await aesDec(b64d(rec.k), b64d(d), recAd(rec)))); // raw bundle; adopt() verifies it
}

// Short code shown on both devices during linking, so a swapped QR is noticed.
async function linkCode(pub) {
  // 12 digits (~40 bits): grinding a matching key inside the 10-minute window is impractical.
  const h = await sha(b64d(pub));
  return String(BigInt('0x' + h.slice(0, 16)) % 1000000000000n).padStart(12, '0').replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3');
}

// ---------- vault: encryption of everything stored on this device ----------
// A random 32-byte master secret gives an AES key for records and an HMAC key that
// blinds contact ids in index fields. The master secret itself is wrapped by the
// Android Keystore, by a passphrase (app lock), or stored as-is in a plain browser.
async function vaultKeys(mk) {
  const base = await crypto.subtle.importKey('raw', mk, 'HKDF', false, ['deriveKey']);
  const p = info => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('lullwire/vault/v1/' + info) });
  const [key, blind] = await Promise.all([
    crypto.subtle.deriveKey(p('enc'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    crypto.subtle.deriveKey(p('blind'), base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign'])]);
  return { key, blind };
}
const blindId = async (vk, id) => hex(await crypto.subtle.sign('HMAC', vk.blind, enc.encode(String(id)))).slice(0, 32);
// pack/unpack turn records with byte arrays and ratchet keys into JSON and back.
const keyJwk = new WeakMap();
const isKey = v => typeof CryptoKey !== 'undefined' && v instanceof CryptoKey;
async function pack(v) {
  if (v instanceof Uint8Array) return { $u: b64e(v) };
  if (isKey(v)) {
    let j = keyJwk.get(v);
    if (!j) { j = await crypto.subtle.exportKey('jwk', v); keyJwk.set(v, j); }
    return { $k: { kty: j.kty, crv: j.crv, x: j.x, y: j.y, d: j.d } };
  }
  if (Array.isArray(v)) return Promise.all(v.map(pack));
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, x] of Object.entries(v)) if (x !== undefined && typeof x !== 'function') o[k] = await pack(x);
    return o;
  }
  return v;
}
async function unpack(v) {
  if (Array.isArray(v)) return Promise.all(v.map(unpack));
  if (v && typeof v === 'object') {
    if (typeof v.$u === 'string') return b64d(v.$u);
    if (v.$k) { const k = await crypto.subtle.importKey('jwk', v.$k, ALG, true, ['deriveBits']); keyJwk.set(k, v.$k); return k; }
    const o = {};
    for (const [k, x] of Object.entries(v)) o[k] = await unpack(x);
    return o;
  }
  return v;
}
// Records are bound to where they are stored (store name and key), so they can't be swapped.
const sealRecord = async (vk, where, obj) => aesEncK(vk.key, enc.encode(JSON.stringify(await pack(obj))), enc.encode('lullwire/vault|' + where));
const openRecord = async (vk, where, bytes) => unpack(JSON.parse(dec.decode(await aesDecK(vk.key, u8(bytes), enc.encode('lullwire/vault|' + where)))));
async function wrapWithPass(mk, pass) {
  const salt = rand(16);
  return { salt: b64e(salt), w: b64e(await aesEnc(await passKey(pass, salt), mk, enc.encode('lullwire/vault/pass'))) };
}
const unwrapWithPass = async (hdr, pass) => aesDec(await passKey(pass, b64d(hdr.salt)), b64d(hdr.w), enc.encode('lullwire/vault/pass'));

// ---------- files ----------
// A file travels as pieces of 192 KiB, each an ordinary end-to-end encrypted message
// ({t:'file', id, i, n, size, name, type, h, d}), so relays carry it like chat: sealed,
// padded, and kept until the recipient collects it. h is SHA-256 of the whole file,
// checked once every piece is in. 16 MiB at most: relays keep 48 MiB per mailbox.
const FILE_CHUNK = 192 * 1024, MAX_FILE = 16 * 1024 * 1024;
const fileChunkCount = size => Math.max(1, Math.ceil(size / FILE_CHUNK));
// A name to show and save under: no folders, control characters or leading dots.
const fileName = s => String(s || '').replace(/[\u0000-\u001f\u007f/\\]/g, '_').replace(/^\.+/, '_').slice(0, 120) || 'file';
const fileType = s => typeof s === 'string' && s.length <= 100 && /^[a-z0-9][\w.+-]*\/[\w.+-]+$/i.test(s) ? s.toLowerCase() : 'application/octet-stream';
// The pieces of a file, as the messages that carry them.
function filePieces(bytes, meta) {
  const n = fileChunkCount(bytes.length), out = [];
  for (let i = 0; i < n; i++) out.push({ t: 'file', id: meta.id, i, n, size: bytes.length, name: meta.name, type: meta.type, h: meta.h, d: b64e(bytes.subarray(i * FILE_CHUNK, (i + 1) * FILE_CHUNK)) });
  return out;
}
// Checks one received piece; null if anything about it is off.
function checkFilePiece(m) {
  if (!m || m.t !== 'file' || typeof m.id !== 'string' || !/^[0-9a-f]{16}$/.test(m.id) || typeof m.h !== 'string' || !/^[0-9a-f]{64}$/.test(m.h)) return null;
  if (!Number.isInteger(m.size) || m.size < 0 || m.size > MAX_FILE) return null;
  const n = fileChunkCount(m.size);
  if (m.n !== n || !Number.isInteger(m.i) || m.i < 0 || m.i >= n || typeof m.d !== 'string') return null;
  let d; try { d = b64d(m.d); } catch { return null; }
  if (d.length !== (m.i < n - 1 ? FILE_CHUNK : m.size - FILE_CHUNK * (n - 1))) return null;
  return { id: m.id, i: m.i, n, size: m.size, h: m.h, name: fileName(m.name), type: fileType(m.type), d };
}

// ---------- delivery over HTTPS ----------
// The mailbox leads the body ("send"), so web server access logs never record who gets
// mail. LEGACY: relays before 0.6.1 only know "put", with the mailbox in the URL; they
// answer "send" with 400 "bad action" (PHP) or "bad s" (Go), and are remembered.
const putOnly = new Set();
async function postMail(relay, box, body) {
  const headers = { 'Content-Type': 'text/plain' };
  if (!putOnly.has(relay)) {
    const r = await fetch(relay + '?a=send', { method: 'POST', headers, body: concat(enc.encode(box), body) });
    if (r.status !== 400) return r;
    const e = await r.clone().json().catch(() => ({}));
    if (e.error !== 'bad action' && e.error !== 'bad s') return r;
    putOnly.add(relay);
  }
  return fetch(relay + '?a=put&box=' + box, { method: 'POST', headers, body });
}

if (typeof module !== 'undefined') module.exports = {
  newIdentity, keysFromJwk, encryptFor, decryptFrom, sealOuter, openOuter, genKP, safetyNumber, contactId, pad,
  rotatePrekeys, makeCard, checkCard, takeCard, usablePrekey, SPK_ROTATE, SPK_USE, SPK_KEEP,
  BACKUP_CONTACTS, backupData, restoreData, exportBackup, importBackup, openBackup, genWords, normWords, recoveryKeys, sealRecovery, openRecovery,
  linkCode, isRelay, b64e, b64d, hex, rand, sha,
  vaultKeys, blindId, pack, unpack, sealRecord, openRecord, wrapWithPass, unwrapWithPass, postMail,
  FILE_CHUNK, MAX_FILE, filePieces, checkFilePiece, fileName, fileType
};

// ---------- storage: an encrypted vault in IndexedDB ----------
// "lullwire" holds only ciphertext, except the vault header (how the master secret is
// protected). Contacts and messages are indexed by blinded ids. "hush2" is the
// plaintext store of 0.5 and earlier; it is migrated once and then deleted.
const DB_NAME = 'lullwire';
let db = null, vk = null, vaultHdr = null, mkRaw = null;
function openDB(name, upgrade, version = 1) {
  return new Promise((res, rej) => {
    const r = indexedDB.open(name, version);
    r.onupgradeneeded = e => { if (!upgrade(r.result, e.oldVersion, r.transaction)) r.transaction.abort(); };
    r.onsuccess = () => res(r.result);
    r.onerror = () => { r.error && r.error.name === 'AbortError' ? res(null) : rej(r.error); };
  });
}
const openVaultDB = () => openDB(DB_NAME, (d, oldVersion) => {
  if (oldVersion < 1) {
    d.createObjectStore('meta');
    d.createObjectStore('kv');
    d.createObjectStore('contacts', { keyPath: 'id' });
    d.createObjectStore('messages', { keyPath: 'id', autoIncrement: true }).createIndex('cid', ['c', 'id']);
  }
  if (oldVersion < 2) d.createObjectStore('files'); // version 2 (0.7): file pieces
  return true;
}, 2);
// Opens the 0.5 store only if it exists (never creates it).
const openLegacyDB = () => openDB('hush2', (d, oldVersion) => oldVersion > 0);
function txOn(d, store, mode, fn) {
  return new Promise((res, rej) => {
    const t = d.transaction(store, mode), req = fn(t.objectStore(store));
    t.oncomplete = () => res(req && req.result);
    t.onerror = () => rej(t.error);
    t.onabort = () => rej(t.error || new DOMException('aborted', 'AbortError'));
  });
}
const tx = (store, mode, fn) => txOn(db, store, mode, fn);
async function useVault(mk) { mkRaw = mk; vk = await vaultKeys(mk); }
// Writes to one record are queued, so a slow seal can't overwrite a newer state.
const writeQ = new Map();
function queued(key, fn) {
  const p = (writeQ.get(key) || Promise.resolve()).then(fn);
  writeQ.set(key, p.catch(() => {}));
  return p;
}
async function kvGet(k) {
  const r = await tx('kv', 'readonly', s => s.get(k));
  return r ? openRecord(vk, 'kv|' + k, r.d) : undefined;
}
const kvSet = (k, v) => queued('kv|' + k, async () => { const d = await sealRecord(vk, 'kv|' + k, v); return tx('kv', 'readwrite', s => s.put({ d }, k)); });
const blinds = new Map();
async function blindOf(id) { let b = blinds.get(id); if (!b) { b = await blindId(vk, id); blinds.set(id, b); } return b; }
const saveContact = c => queued('c|' + c.id, async () => {
  const id = await blindOf(c.id);
  const d = await sealRecord(vk, 'contacts|' + id, c);
  return tx('contacts', 'readwrite', s => s.put({ id, d }));
});
async function loadContacts() {
  const out = [];
  for (const r of (await tx('contacts', 'readonly', s => s.getAll())) || []) {
    try { const c = await openRecord(vk, 'contacts|' + r.id, r.d); blinds.set(c.id, r.id); out.push(c); }
    catch (e) { console.warn('unreadable contact record', e); }
  }
  return out;
}
async function dropContact(id) {
  const b = await blindOf(id);
  try { for (const m of (await messagesFor(id, 1e6)).list) if (m.file && m.file.sid) await dropPieces(m.file.sid); }
  catch (e) { console.warn('file cleanup', e); }
  await queued('c|' + id, () => tx('contacts', 'readwrite', s => s.delete(b)));
  await tx('messages', 'readwrite', s => {
    const req = s.index('cid').openKeyCursor(IDBKeyRange.bound([b, 0], [b, Infinity]));
    req.onsuccess = () => { const cur = req.result; if (cur) { s.delete(cur.primaryKey); cur.continue(); } };
  });
}
// File pieces: stored under a local id (sid), each encrypted with the file's own key
// (fk), which lives in the file's message record inside the vault.
const pieceAD = (f, i) => enc.encode('lullwire/file|' + f.sid + '|' + i);
async function putPiece(f, i, bytes) {
  const ct = await aesEnc(f.fk, bytes, pieceAD(f, i));
  return tx('files', 'readwrite', s => s.put(ct, f.sid + '|' + i));
}
async function getPiece(f, i) {
  const ct = await tx('files', 'readonly', s => s.get(f.sid + '|' + i));
  return ct ? aesDec(f.fk, u8(ct), pieceAD(f, i)) : null;
}
async function fileBytes(f) {
  const parts = [];
  for (let i = 0; i < f.n; i++) { const p = await getPiece(f, i); if (!p) return null; parts.push(p); }
  return concat(...parts);
}
const dropPieces = sid => tx('files', 'readwrite', s => s.delete(IDBKeyRange.bound(sid + '|', sid + '|\uffff')));
async function putMessage(m) {
  const c = await blindOf(m.contact), { id, ...rest } = m;
  const rec = { c, d: await sealRecord(vk, 'messages|' + c, rest) };
  if (id !== undefined) rec.id = id;
  return tx('messages', 'readwrite', s => s.put(rec));
}
// The newest `limit` messages with a contact (oldest first), and whether there are more.
async function messagesFor(contact, limit) {
  const c = await blindOf(contact), recs = [];
  await new Promise((res, rej) => {
    const t = db.transaction('messages', 'readonly');
    const req = t.objectStore('messages').index('cid').openCursor(IDBKeyRange.bound([c, 0], [c, Infinity]), 'prev');
    req.onsuccess = () => { const cur = req.result; if (cur && recs.length <= limit) { recs.push(cur.value); cur.continue(); } };
    t.oncomplete = res; t.onerror = () => rej(t.error);
  });
  const more = recs.length > limit, list = [];
  for (const r of recs.slice(0, limit).reverse()) {
    try { list.push({ ...(await openRecord(vk, 'messages|' + c, r.d)), id: r.id }); } catch (e) { console.warn('unreadable message', e); }
  }
  return { list, more };
}

// ---------- app ----------
if (typeof document !== 'undefined') (() => {
  const $ = s => document.querySelector(s);
  const TP = { 'Content-Type': 'text/plain' };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const jitter = ms => Math.round(ms * (0.7 + Math.random() * 0.6));
  let me = null, current = null, started = false, paused = false, pendingInvite = null;
  const contacts = new Map(), seen = new Set(), locks = new Map();
  // Serialize work per contact: sends, receives and every change the user makes (verify,
  // block, delete, accept) run one at a time, so none can undo another.
  const lock = (id, fn) => { const p = (locks.get(id) || Promise.resolve()).then(fn); locks.set(id, p.catch(() => {})); return p; };
  // Change a contact under its lock and save it. fn returns false to skip saving.
  const edit = (id, fn) => lock(id, async () => {
    const c = contacts.get(id); if (!c) return null;
    if ((await fn(c)) !== false) await saveContact(c);
    return c;
  });

  // ----- small helpers -----
  let toastTimer;
  function toast(t, ms) {
    $('#toast').textContent = t || '';
    clearTimeout(toastTimer);
    if (t && ms !== 0) toastTimer = setTimeout(() => { $('#toast').textContent = ''; }, ms || 2600);
  }
  const fromStd = d => Uint8Array.from(atob(d), ch => ch.charCodeAt(0));
  const parseHashData = (text, key) => {
    const m = String(text).match(new RegExp('#' + key + '=([A-Za-z0-9_-]+)'));
    return m ? JSON.parse(dec.decode(b64d(m[1]))) : null;
  };
  // Inside the Android app the page has no relay next to it, and links must point at a
  // web copy of the app people can open: the one your relay serves.
  const AND = window.LullwireAndroid || null;
  const has = fn => !!(AND && typeof AND[fn] === 'function');
  const CONFIG = window.LULLWIRE_CONFIG || window.HUSH_CONFIG || {}; // LEGACY: config.js files written for Hush Relay
  const defaultRelay = () => CONFIG.relay || (AND ? '' : new URL('relay.php', location.href).href);
  const linkBase = relay => AND ? String(relay).replace(/[?#].*$/, '').replace(/[^/]*$/, '') : location.origin + location.pathname;
  async function copyText(text) {
    if (AND) { AND.copy(text); return; }
    await navigator.clipboard.writeText(text);
  }
  const COLORS = ['#0e7a68', '#2f6db3', '#8a4fbf', '#c2410c', '#0f766e', '#b4235a', '#4d7c0f', '#6b5b95', '#9a6b00', '#1d6f8a'];
  function paintAvatar(el, name, key) {
    const words = String(name || '?').trim().split(/\s+/);
    el.textContent = ((words[0] || '?')[0] + (words.length > 1 ? words[words.length - 1][0] : '')).toUpperCase();
    let h = 0; for (const ch of String(key || name)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    el.style.background = COLORS[h % COLORS.length];
  }
  function fmtTime(ts) {
    const d = new Date(ts), now = new Date();
    return d.toDateString() === now.toDateString()
      ? d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
      : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ', ' + d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  }
  const fmtDur = s => Math.floor(s / 60) + ':' + String(Math.floor(s % 60)).padStart(2, '0');
  const INVITE_USES = 25; // people one invite link adds as contacts before the rest arrive as requests
  const isHex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/.test(s);
  const SVG_NS = 'http://www.w3.org/2000/svg';
  function svgIcon(cls, paths, width) {
    const s = document.createElementNS(SVG_NS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor');
    s.setAttribute('stroke-width', width || '2'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round');
    if (cls) s.setAttribute('class', cls);
    for (const d of paths) { const p = document.createElementNS(SVG_NS, 'path'); p.setAttribute('d', d); s.append(p); }
    return s;
  }

  // ----- the profile record (keys live in the vault, not in this object on disk) -----
  async function saveMe() {
    const { priv, sign, card, jwk, spks, ...rest } = me;
    rest.spks = (spks || []).map(k => ({ pub: k.pub, t: k.t, jwk: k.jwk }));
    return kvSet('me', rest);
  }
  async function loadMe() {
    const r = await kvGet('me'); if (!r) return null;
    const id = await kvGet('identity'); if (!id || !id.jwk) throw new Error('identity key missing');
    r.spks = await Promise.all((r.spks || []).map(async k => ({ ...k, priv: await prekeyPriv(k.jwk) })));
    return { ...r, ...(await keysFromJwk(id.jwk)) };
  }
  const saveIdentity = jwk => kvSet('identity', { jwk });
  const identityJwk = async () => (await kvGet('identity')).jwk;
  const bundle = async () => backupData({ ...me, jwk: await identityJwk() }, [...contacts.values()]);

  // What a relay supports. Older (PHP) relays don't know "info": treat them as open, no calls.
  async function relayInfo(url) {
    if (!isRelay(url)) return { ok: false, invite: false, calls: false, mail: false };
    try {
      const r = await fetch(url + '?a=info', { method: 'POST', headers: TP, body: '{}' });
      if (!r.ok) return { ok: r.status === 400, invite: false, calls: false, mail: false };
      const j = await r.json();
      return { ok: true, invite: !!j.invite, calls: !!j.calls, mail: !!j.mail };
    } catch { return { ok: false, invite: false, calls: false, mail: false }; }
  }
  // The live endpoint lives next to the relay: …/relay.php -> …/live, https -> wss.
  function liveURL(relay) {
    const u = new URL(relay);
    u.pathname = u.pathname.replace(/[^/]*$/, 'live');
    u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
    return u.href;
  }

  // ----- views -----
  const views = ['vLock', 'vSetup', 'vList', 'vInvite', 'vAdd', 'vScan', 'vChat', 'vSafety', 'vPair', 'vLink', 'vSettings'];
  function show(v, title, sub) {
    for (const x of views) $('#' + x).hidden = x !== v;
    $('#title').textContent = title || 'Lullwire Relay';
    $('#subtitle').textContent = sub || ''; $('#subtitle').hidden = !sub;
    $('#brandDot').hidden = v !== 'vList' && v !== 'vSetup' && v !== 'vLock';
    $('#back').hidden = !me || v === 'vList' || v === 'vSetup' || v === 'vLock';
    $('#settingsBtn').hidden = $('#scanBtn').hidden = v !== 'vList';
    const callable = v === 'vChat' && me && me.calls && self.LullwireCall && LullwireCall.supported();
    $('#voiceBtn').hidden = $('#videoBtn').hidden = !callable;
    if (v !== 'vChat' && v !== 'vSafety') current = null;
    if (v !== 'vScan') stopScanner();
  }
  function goHome() { show('vList'); renderList(); }

  // ----- QR -----
  const scripts = {};
  const loadScript = src => scripts[src] || (scripts[src] = new Promise((res, rej) => {
    const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = rej; document.head.append(s);
  }));
  async function renderQR(img, text) {
    await loadScript('vendor/qrcode.js');
    const q = qrcode(0, 'L'); q.addData(text); q.make();
    img.src = q.createDataURL(5, 3);
  }
  let detector;
  async function decodeQR(src, w, h) {
    if (detector === undefined) {
      detector = null;
      try { if ('BarcodeDetector' in self && (await BarcodeDetector.getSupportedFormats()).includes('qr_code')) detector = new BarcodeDetector({ formats: ['qr_code'] }); } catch {}
    }
    if (detector) { try { const r = await detector.detect(src); if (r[0]) return r[0].rawValue; } catch {} }
    await loadScript('vendor/jsQR.js');
    const s = Math.min(1, 1000 / Math.max(w, h)), cw = Math.round(w * s), ch = Math.round(h * s);
    const cv = document.createElement('canvas'); cv.width = cw; cv.height = ch;
    const ctx = cv.getContext('2d', { willReadFrequently: true }); ctx.drawImage(src, 0, 0, cw, ch);
    const r = self.jsQR(ctx.getImageData(0, 0, cw, ch).data, cw, ch);
    return r ? r.data : null;
  }
  let camera = null;
  async function openScanner() {
    show('vScan', 'Scan a code');
    $('#scanNote').textContent = 'Point the camera at an invite or a move code, or choose a picture of one.';
    const v = $('#scanVideo');
    try {
      camera = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      v.srcObject = camera; v.hidden = false; await v.play(); scanTick();
    } catch { v.hidden = true; $('#scanNote').textContent = 'Camera not available. Choose a picture of the code instead.'; }
  }
  function stopScanner() { if (camera) { camera.getTracks().forEach(t => t.stop()); camera = null; } }
  async function scanTick() {
    if (!camera) return;
    const v = $('#scanVideo');
    if (v.videoWidth) {
      const t = await decodeQR(v, v.videoWidth, v.videoHeight);
      if (t && camera) { stopScanner(); return handleCode(t); }
    }
    setTimeout(scanTick, 300);
  }
  async function handleCode(text) {
    try {
      if (/#link=/.test(text)) return await showLinkRequest(text);
      if (/#i=/.test(text)) { const c = await addFromInvite(text); return openChat(c.id); }
      throw new Error('That is not a Lullwire Relay code');
    } catch (e) { alert(e.message); goHome(); }
  }

  // ----- contacts & invites -----
  function newContact(id, p, b, r, n) {
    return { id, pub: p, box: b, relay: r, name: String(n || 'Unknown').slice(0, 40), unread: 0, ts: Date.now(),
      verified: false, blocked: false, sessions: {}, active: null, last: '' };
  }
  // An invite holds only what's needed to reach you, plus your relay's join code
  // (so friends can sign up on it), a token that marks them as invited by you, and
  // your signed card (so nobody can swap the mailbox in it, and the first messages
  // get forward secrecy).
  async function inviteLink() {
    const o = { p: me.pub, b: me.box, r: me.relay, n: me.name, k: me.inviteTok, q: await makeCard(me) };
    if (me.join) o.j = me.join;
    return linkBase(me.relay) + '#i=' + b64e(enc.encode(JSON.stringify(o)));
  }
  function readInvite(text) {
    const o = parseHashData(text, 'i');
    if (!o || typeof o.p !== 'string') throw new Error('That does not look like an invite link');
    if (!isBox(o.b) || !isRelay(o.r)) throw new Error('This invite is incomplete');
    return o;
  }
  async function addFromInvite(text) {
    const o = readInvite(text);
    if (o.p === me.pub) throw new Error('That is your own invite');
    await importPub(o.p);
    const id = await contactId(o.p);
    let fresh = false;
    const c = await lock(id, async () => {
    let c = contacts.get(id);
    if (c) {
      if (c.blocked) {
        if (!confirm(c.name + ' is blocked. Unblock them?')) return c;
        c.blocked = false;
      }
      if (c.box !== o.b || c.relay !== o.r) {
        // A newer card signed by their key moves them safely; an unsigned (older app)
        // invite never silently re-routes an existing contact.
        if (await takeCard(c, o.b, o.r, o.q)) { c.box = o.b; c.relay = o.r; toast(c.name + '\'s new address was verified'); }
        else if (confirm('This invite has a different address for ' + c.name + ' than the one you have, and it isn\'t signed by them. Only switch if they told you they moved. Switch?')) {
          c.box = o.b; c.relay = o.r;
        }
      } else await takeCard(c, o.b, o.r, o.q);
      c.request = false;
    } else {
      c = newContact(id, o.p, o.b, o.r, o.n);
      if (o.q !== undefined) {
        // A Lullwire invite is signed: if its address doesn't match the signature, someone changed it.
        if (!(await takeCard(c, o.b, o.r, o.q))) throw new Error('This invite was changed or damaged on the way: its signature doesn\'t match. Ask ' + c.name + ' for a new one.');
      } else if (!confirm('This invite comes from an older app (Hush Relay), so its address isn\'t signed. Add ' + c.name + ' anyway? Compare safety codes once you\'re chatting.')) {
        throw new Error('Not added');
      }
      contacts.set(id, c); fresh = true;
    }
    await saveContact(c);
    return c;
    });
    scheduleSync();
    // Say hello so they see you straight away (and know you came from their invite).
    if (fresh && typeof o.k === 'string') post(c, { t: 'hello', k: o.k.slice(0, 64), id: hex(rand(8)), ts: Date.now() }).catch(() => {});
    return c;
  }

  // ----- contact list -----
  async function renderList() {
    const ul = $('#contactList'); ul.textContent = '';
    const arr = [...contacts.values()].filter(c => !c.blocked).sort((a, b) => b.ts - a.ts);
    $('#empty').hidden = arr.length > 0;
    for (const c of arr) {
      const li = document.createElement('li'); li.className = 'contact';
      const av = document.createElement('span'); av.className = 'avatar'; paintAvatar(av, c.name, c.id);
      const who = document.createElement('div'); who.className = 'who';
      const nm = document.createElement('div'); nm.className = 'nm';
      const nmText = document.createElement('span'); nmText.textContent = c.name; nm.append(nmText);
      if (c.verified) { const ck = svgIcon('check', ['M20 6L9 17l-5-5'], '2.6'); ck.setAttribute('aria-label', 'Verified'); nm.append(ck); }
      if (c.request) { const t = document.createElement('span'); t.className = 'tag'; t.textContent = 'Request'; nm.append(t); }
      const pv = document.createElement('div'); pv.className = 'pv'; pv.textContent = c.last || (c.request ? 'Wants to message you' : 'Say hello');
      who.append(nm, pv);
      li.append(av, who);
      if (c.unread) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = c.unread; li.append(b); }
      li.onclick = () => openChat(c.id);
      ul.append(li);
    }
  }

  // ----- chat -----
  const PAGE = 100;
  let shown = PAGE;
  const trustLabel = c => c.request ? 'Message request' : c.verified ? 'Verified' : 'Not verified yet';
  async function openChat(id) {
    const c = contacts.get(id); if (!c) return;
    if (!net.ok) wake(false); // don't make someone opening a chat wait out a retry delay
    if (current !== id) shown = PAGE;
    show('vChat', c.name, trustLabel(c)); current = id;
    if (c.unread) await edit(id, x => { if (!x.unread) return false; x.unread = 0; });
    renderTrust(c);
    await renderMsgs();
  }
  function renderTrust(c) {
    const b = $('#trustBar');
    b.hidden = c.verified && !c.request;
    b.className = 'trust'; b.textContent = '';
    const t = document.createElement('span');
    t.textContent = c.request
      ? 'Someone new wants to message you. Names can be faked: check their safety code. Replying accepts the request.'
      : 'Tap to compare your safety code with ' + c.name + ' once, so you know nobody is in the middle.';
    b.append(svgIcon('', ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z']), t);
    b.onclick = () => openSafety(c.id);
  }
  async function openSafety(id) {
    const c = contacts.get(id); if (!c) return;
    show('vSafety', 'Safety code'); current = id;
    paintAvatar($('#safAvatar'), c.name, c.id);
    $('#safName').textContent = c.name;
    $('#safState').textContent = c.verified ? 'You verified this contact.' : c.request ? 'Message request · not verified' : 'Not verified yet';
    const grid = $('#safetyGrid'); grid.textContent = '';
    for (const g of (await safetyNumber(me.pub, c.pub)).split(' ')) { const s = document.createElement('span'); s.textContent = g; grid.append(s); }
    $('#verifyBtn').hidden = c.verified;
    $('#deleteReqBtn').textContent = c.request ? 'Delete request' : 'Delete contact';
  }
  $('#verifyBtn').onclick = async () => {
    const c = contacts.get(current); if (!c) return;
    await edit(c.id, x => { x.verified = true; }); scheduleSync(); toast('Verified'); openChat(c.id);
  };
  $('#deleteReqBtn').onclick = async () => {
    const c = contacts.get(current); if (!c) return;
    if (!c.request && !confirm('Delete ' + c.name + ' and your chat history with them? They can still message you later, as a new request.')) return;
    await lock(c.id, async () => { contacts.delete(c.id); await dropContact(c.id); });
    if (!c.request) scheduleSync(); goHome();
  };
  $('#blockBtn').onclick = async () => {
    const c = contacts.get(current); if (!c) return;
    if (!confirm('Block ' + c.name + '? You won\'t receive their messages.')) return;
    await edit(c.id, x => { x.blocked = true; }); scheduleSync(); goHome();
  };

  let renderSeq = 0;
  async function renderMsgs() {
    if (!current) return;
    const seq = ++renderSeq, id = current;
    const { list, more } = await messagesFor(id, shown);
    if (seq !== renderSeq || current !== id) return; // a newer render took over
    const ol = $('#msgs'), atBottom = ol.scrollHeight - ol.scrollTop - ol.clientHeight < 40, prevH = ol.scrollHeight;
    ol.textContent = '';
    if (more) {
      const b = document.createElement('button'); b.className = 'more'; b.textContent = 'Show earlier messages';
      b.onclick = () => { shown += PAGE; keepPos = true; renderMsgs(); };
      ol.append(b);
    }
    for (const m of list) {
      const li = document.createElement('li');
      li.className = 'm ' + m.dir + (m.state === 'failed' ? ' failed' : '') + (m.file ? ' has-file' : '');
      if (m.file) li.append(fileView(m)); else li.textContent = m.txt;
      if (m.dir !== 'sys') {
        const s = document.createElement('small');
        s.textContent = fmtTime(m.ts) + (m.dir === 'out' && !m.file ? ' · ' + (m.state === 'failed' ? 'not sent, tap to retry' : m.state) : '');
        li.append(s);
      }
      if (m.state === 'failed') li.onclick = () => (m.file ? deliverFile : deliver)(contacts.get(m.contact), m);
      ol.append(li);
    }
    if (keepPos) { ol.scrollTop = ol.scrollHeight - prevH; keepPos = false; }
    else if (atBottom || seq === 1 || ol.dataset.for !== id) ol.scrollTop = ol.scrollHeight;
    ol.dataset.for = id;
  }
  let keepPos = false;
  async function note(c, txt) {
    await putMessage({ contact: c.id, dir: 'sys', txt, ts: Date.now() });
    if (current === c.id) renderMsgs();
  }

  async function post(c, msg) {
    const blob = await lock(c.id, async () => { const b = await encryptFor(me, c, msg); await saveContact(c); return b; });
    return putMail(c, blob);
  }
  async function deliver(c, m) {
    m.state = 'sending'; await putMessage(m); renderMsgs();
    try { m.state = (await post(c, { t: 'msg', id: m.mid, txt: m.txt, ts: m.ts })) ? 'sent' : 'failed'; }
    catch (e) { console.warn(e); m.state = 'failed'; }
    await putMessage(m); renderMsgs();
  }
  async function send(text) {
    const c = contacts.get(current); if (!c || !text.trim()) return;
    if (c.request) { await edit(c.id, x => { x.request = false; }); scheduleSync(); renderTrust(c); show('vChat', c.name, trustLabel(c)); current = c.id; }
    const m = { contact: c.id, dir: 'out', txt: text, ts: Date.now(), mid: hex(rand(8)), state: 'sending' };
    m.id = await putMessage(m);
    await edit(c.id, x => { x.ts = m.ts; x.last = 'You: ' + text.slice(0, 80); });
    await deliver(c, m);
  }

  // ----- files -----
  const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? Math.round(n / 1024) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
  const PREVIEW = /^image\/(png|jpeg|gif|webp|avif)$/; // raster images only, shown in an <img>
  const previews = new Map(); // message id -> object URL
  function fileView(m) {
    const f = m.file, box = document.createElement('div'), name = document.createElement('b'), meta = document.createElement('span');
    box.className = 'file';
    name.textContent = f.name;
    const pct = k => Math.floor(100 * (k || 0) / f.n) + '%';
    meta.textContent = fmtSize(f.size) + ' · ' + (m.dir === 'out'
      ? (m.state === 'failed' ? 'not sent, tap to retry' : m.state === 'sending' ? 'sending ' + pct(f.done) : 'sent')
      : m.state === 'receiving' ? 'receiving ' + pct(f.got) : m.state === 'corrupt' ? 'damaged on the way, ask for it again' : 'received');
    box.append(name, meta);
    if (m.dir === 'out' || m.state === 'done') {
      if (PREVIEW.test(f.type)) {
        const img = document.createElement('img'); img.alt = f.name; img.className = 'file-img';
        const url = previews.get(m.id);
        if (url) img.src = url;
        else fileBytes(f).then(b => { if (!b) return; const u = URL.createObjectURL(new Blob([b], { type: f.type })); previews.set(m.id, u); img.src = u; }).catch(() => {});
        box.prepend(img);
      }
      const save = document.createElement('button');
      save.type = 'button'; save.className = 'file-save'; save.textContent = 'Save';
      save.onclick = e => { e.stopPropagation(); saveReceived(f); };
      box.append(save);
    }
    return box;
  }
  // Saving never opens the file in the app's own page (a received HTML file could act
  // as the app): the browser downloads it, Android asks where to keep it.
  async function saveReceived(f) {
    const b = await fileBytes(f);
    if (!b) return alert('This file is no longer on this device.');
    if (has('saveBytes')) return AND.saveBytes(f.name, f.type, b64e(b));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([b], { type: 'application/octet-stream' }));
    a.download = f.name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
  }
  async function sendFile(file) {
    const c = contacts.get(current); if (!c || !file) return;
    if (file.size > MAX_FILE) return alert('Files can be up to ' + fmtSize(MAX_FILE) + '. This one is ' + fmtSize(file.size) + '.');
    if (c.request) { await edit(c.id, x => { x.request = false; }); scheduleSync(); renderTrust(c); show('vChat', c.name, trustLabel(c)); current = c.id; }
    let bytes;
    try { bytes = new Uint8Array(await file.arrayBuffer()); } catch { return alert('Could not read that file.'); }
    const f = { sid: hex(rand(8)), fk: rand(32), id: hex(rand(8)), name: fileName(file.name), type: fileType(file.type),
      size: bytes.length, n: Math.max(1, Math.ceil(bytes.length / FILE_CHUNK)), h: await sha(bytes), done: 0 };
    for (let i = 0; i < f.n; i++) await putPiece(f, i, bytes.subarray(i * FILE_CHUNK, (i + 1) * FILE_CHUNK));
    const m = { contact: c.id, dir: 'out', txt: '\u{1F4CE} ' + f.name, ts: Date.now(), mid: f.id, state: 'sending', file: f };
    m.id = await putMessage(m);
    await edit(c.id, x => { x.ts = m.ts; x.last = 'You: \u{1F4CE} ' + f.name; });
    await deliverFile(c, m);
  }
  // Sends the pieces not yet accepted by the relay; a retry picks up where it stopped.
  async function deliverFile(c, m) {
    const f = m.file;
    m.state = 'sending'; await putMessage(m); renderMsgs();
    try {
      for (let i = f.done; i < f.n; i++) {
        const d = await getPiece(f, i);
        if (!d) throw new Error('piece missing');
        const ok = await post(c, { t: 'file', id: f.id, i, n: f.n, size: f.size, name: f.name, type: f.type, h: f.h, d: b64e(d), ts: Date.now() });
        if (!ok) throw new Error('relay refused');
        f.done = i + 1; await putMessage(m); if (current === c.id) renderMsgs();
      }
      m.state = 'sent';
    } catch (e) { console.warn('file not sent', e); m.state = 'failed'; }
    await putMessage(m); renderMsgs();
  }
  // One received piece. Pieces are kept as they come (in any order); once all are in,
  // the whole file is checked against its SHA-256.
  async function receivePiece(c, p) {
    const key = 'file|' + await blindOf('file:' + c.id + ':' + p.id);
    let st = await kvGet(key);
    if (st && st.done) return;
    if (!st) {
      const f = { sid: hex(rand(8)), fk: rand(32), id: p.id, name: p.name, type: p.type, size: p.size, n: p.n, h: p.h, got: 0 };
      const m = { contact: c.id, dir: 'in', txt: '\u{1F4CE} ' + f.name, ts: Date.now(), mid: 'file:' + p.id, state: 'receiving', file: f };
      m.id = await putMessage(m);
      st = { m, have: '0'.repeat(p.n) };
      c.ts = Date.now(); c.last = '\u{1F4CE} ' + f.name;
      if (current !== c.id) c.unread = (c.unread || 0) + 1;
      notify('msg', c, '\u{1F4CE} ' + f.name);
    }
    const f = st.m.file;
    if (p.size !== f.size || p.h !== f.h || p.n !== f.n || st.have[p.i] === '1') return; // pieces of one file must agree
    await putPiece(f, p.i, p.d);
    st.have = st.have.slice(0, p.i) + '1' + st.have.slice(p.i + 1);
    f.got = (f.got || 0) + 1;
    if (f.got === f.n) {
      const all = await fileBytes(f);
      st.m.state = all && (await sha(all)) === f.h ? 'done' : 'corrupt';
      if (st.m.state === 'corrupt') await dropPieces(f.sid);
      st.done = true;
    }
    await putMessage(st.m);
    await kvSet(key, st);
  }

  // ----- notifications (Android app) -----
  function notify(kind, c, text) {
    if (!has('notify') || (document.visibilityState === 'visible' && current === c.id)) return;
    const named = me.notifyNames;
    AND.notify(kind, kind === 'call' ? (named ? c.name : 'Incoming call') : (named ? c.name : 'Lullwire Relay'),
      kind === 'call' ? (named ? text : 'Open Lullwire Relay to answer') : (named ? text.slice(0, 120) : 'New message'));
  }

  // ----- receive -----
  async function receive(bytes) {
    const inner = await openOuter(me, bytes);
    if ((inner.v !== 2 && inner.v !== 4) || typeof inner.f !== 'string' || inner.f === me.pub) throw new Error('unsupported message');
    const id = await contactId(inner.f);
    let callMsg = null, changed = false;
    await lock(id, async () => {
      // Work on a copy: if storing fails, the contact's ratchet hasn't moved and the
      // envelope (left on the relay) decrypts again on the next try.
      const orig = contacts.get(id);
      let c = orig && structuredClone(orig), isNew = false;
      if (c && c.blocked) return;
      if (!c) {
        if (!isBox(inner.b) || !isRelay(inner.r)) throw new Error('bad sender data');
        await importPub(inner.f);
        c = newContact(id, inner.f, inner.b, inner.r, inner.n); isNew = true;
        c.request = true; // a stranger: shown as a request until you reply or accept
      }
      const msg = await decryptFrom(me, c, inner); // throws unless the sender really holds that identity key
      // A newer card, signed by their identity key, moves them; for older apps only the
      // newest live session may change where we send replies (a replay can't re-route us).
      if (await takeCard(c, inner.b, inner.r, inner.q)) { c.box = inner.b; c.relay = inner.r; }
      else if (!isNew && !c.v4 && c.active === inner.s && isBox(inner.b) && isRelay(inner.r)) { c.box = inner.b; c.relay = inner.r; }
      if (isNew) {
        // Strangers can't crowd out real contacts: at most 200 open requests, oldest dropped first.
        const reqs = [...contacts.values()].filter(x => x.request).sort((a, b) => a.ts - b.ts);
        for (const old of reqs.slice(0, Math.max(0, reqs.length - 199))) { contacts.delete(old.id); await dropContact(old.id); }
        if ([...contacts.values()].filter(x => !x.request && !x.blocked).length >= 5000) return;
      }
      const dup = typeof msg.id === 'string' && seen.has(id + ':' + msg.id);
      if (msg.t === 'msg' && typeof msg.txt === 'string' && !dup) {
        await putMessage({ contact: id, dir: 'in', txt: msg.txt.slice(0, 4000), ts: Date.now(), mid: msg.id });
        c.ts = Date.now(); c.last = msg.txt.slice(0, 80);
        if (current !== id) c.unread = (c.unread || 0) + 1;
        if (!c.request) notify('msg', c, msg.txt);
      } else if (msg.t === 'hello' && !dup) {
        // Someone joined through your invite: they're expected, not a stranger.
        // An invite link can be forwarded, so it only auto-accepts a limited number of
        // people; after that (or after you make a new link) they arrive as requests.
        if (isNew && me.inviteTok && msg.k === me.inviteTok && (me.inviteUses || 0) < INVITE_USES) {
          c.request = false; me.inviteUses = (me.inviteUses || 0) + 1; await saveMe();
        }
        c.ts = Date.now(); c.last = c.request ? 'Wants to message you' : 'Joined with your invite';
        await putMessage({ contact: id, dir: 'sys', txt: c.name + (c.request ? ' wants to message you.' : ' joined using your invite.'), ts: Date.now() });
        if (current !== id) c.unread = (c.unread || 0) + 1;
      } else if (msg.t === 'reset' && c.opened === inner.s) {
        // The contact moved to a new device (or updated the app): this new session replaces all earlier ones.
        c.active = inner.s;
        for (const s of Object.keys(c.sessions)) if (s !== inner.s) delete c.sessions[s];
        await putMessage({ contact: id, dir: 'sys', ts: Date.now(), txt: msg.why === 'upgrade'
          ? c.name + ' updated their app. Your secure session was renewed.'
          : c.name + ' signed in on a new device. Anything sent to them just before may be lost.' });
      } else if (msg.t === 'file' && !c.request) {
        const p = checkFilePiece(msg);
        if (p) await receivePiece(c, p);
      } else if (/^call/.test(msg.t || '') && !dup) {
        callMsg = { c, msg };
      }
      await saveContact(c);
      if (orig) { Object.assign(orig, c); c = orig; } // keep one object per contact (the UI holds it)
      contacts.set(id, c);
      if (typeof msg.id === 'string') seen.add(id + ':' + msg.id);
      if (callMsg) callMsg.c = c;
      changed = true;
      if (!c.request) scheduleSync();
    });
    if (callMsg) onCallMessage(callMsg.c, callMsg.msg);
    return changed;
  }
  const STORAGE_ERRORS = ['QuotaExceededError', 'UnknownError', 'AbortError', 'TransactionInactiveError', 'InvalidStateError'];
  function refreshViews() { if (current && !$('#vChat').hidden) renderMsgs(); else if (!$('#vList').hidden) renderList(); }

  // ----- live delivery -----
  // Preferred: two long-lived WebSockets to your relay. The mail connection (opened
  // with your mailbox secret) receives and acknowledges; the send connection carries
  // deliveries to contacts on the same relay and says nothing about who you are, so the
  // relay can't tie what you send to your mailbox (as with plain HTTPS deliveries).
  // Optional cover traffic on both looks like real deliveries, replies and acks.
  // Fallback: long-polling, for relays (PHP) or proxies without WebSocket support.
  const mail = { ws: null, send: null, reqs: new Map(), seq: 1, fails: 0, pollUntil: 0, kick: null };
  const awake = () => document.visibilityState === 'visible' || !!activeCall || (has('setBackground') && me && me.bg !== false);

  // ----- connection status -----
  // Whether mail can arrive right now, shown in a bar under the header. Phones drop
  // connections without telling anyone when they lock, switch apps or change networks;
  // on coming back (or when the network returns, a chat opens, or Retry is tapped) the
  // app reconnects at once instead of waiting out the retry delay.
  const net = { ok: false, fails: 0, since: Date.now(), retryAt: 0, backoff: 2000, flash: 0, wakers: new Set(), poll: null };
  const GRACE = 2500; // a reconnect this quick isn't worth showing
  function nap(ms) { // a sleep that wake() cuts short
    return new Promise(res => {
      const done = () => { clearTimeout(t); net.wakers.delete(done); res(); };
      const t = setTimeout(done, ms); net.wakers.add(done);
    });
  }
  function paintNet() {
    const bar = $('#netBar'), retry = $('#netRetry'), now = Date.now();
    let text = '', ok = false;
    if (!me || paused || !awake() || ['vSetup', 'vLock', 'vPair'].some(v => !$('#' + v).hidden)) text = '';
    else if (net.ok) { if (now < net.flash) { text = 'Connected'; ok = true; } }
    else if (navigator.onLine === false) text = 'No internet connection. Waiting for it…';
    else if (now - net.since < GRACE && net.fails < 2) text = '';
    else if (net.retryAt > now + 1000) text = 'Offline. Retrying in ' + Math.ceil((net.retryAt - now) / 1000) + ' s';
    else text = 'Connecting…';
    bar.hidden = !text; bar.classList.toggle('ok', ok);
    $('#netText').textContent = text;
    retry.hidden = !text || ok || navigator.onLine === false;
  }
  setInterval(paintNet, 1000);
  function netUp() {
    if (!net.ok) { const shown = !$('#netBar').hidden && !$('#netBar').classList.contains('ok'); net.ok = true; net.flash = shown ? Date.now() + 1500 : 0; }
    net.fails = 0; net.retryAt = 0; net.backoff = 2000; paintNet();
  }
  function netDown() {
    if (net.ok) { net.ok = false; net.since = Date.now(); }
    net.fails++; paintNet();
  }
  async function retryLater() { // after a failed connection: wait (cut short by wake), longer each time
    netDown();
    const d = jitter(net.backoff); net.retryAt = Date.now() + d; paintNet();
    await nap(d);
    net.retryAt = 0; net.backoff = Math.min(net.backoff * 2, 60000); paintNet();
  }
  // Reconnect now. fresh: also drop the current connection, which a phone that slept may
  // have left half-dead (mail on it is sent again: the relay keeps it until acknowledged).
  function wake(fresh) {
    net.backoff = 2000; net.retryAt = 0;
    if (fresh) {
      if (net.poll) net.poll.abort();
      if (mail.kick) mail.kick();
      if (net.ok) { net.ok = false; net.since = Date.now(); net.fails = 0; }
    }
    for (const w of [...net.wakers]) w();
    paintNet();
  }
  $('#netRetry').onclick = () => wake(true);
  let hiddenAt = 0;
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') { hiddenAt = Date.now(); return; }
    const away = hiddenAt ? Date.now() - hiddenAt : 0; hiddenAt = 0;
    wake(away > 15000); // a short glance away leaves a working connection alone
  });
  addEventListener('online', () => wake(true));
  addEventListener('offline', () => { netDown(); });
  addEventListener('pageshow', e => { if (e.persisted) wake(true); });
  const hexBytes = h => Uint8Array.from(h.match(/../g), x => parseInt(x, 16));
  const ENV_MIN = 1024 + 93; // a 1 KiB-class envelope; real ones add a random tail of up to 128 bytes
  function sendFrame(kind, boxBytes, body) {
    const ws = mail.send, r = mail.seq = (mail.seq + 1) >>> 0 || 1;
    const head = new Uint8Array(21); head[0] = kind; new DataView(head.buffer).setUint32(1, r); head.set(boxBytes, 5);
    return new Promise(res => {
      mail.reqs.set(r, res); ws.send(concat(head, body));
      setTimeout(() => { if (mail.reqs.delete(r)) res(null); }, 10000);
    });
  }
  async function putMail(c, blob) {
    if (mail.send && mail.send.readyState === 1 && c.relay === me.relay) {
      const ok = await sendFrame(1, hexBytes(c.box), blob);
      if (ok !== null) return ok; // no answer: send it again over HTTPS (a duplicate is refused by the ratchet)
    }
    const r = await postMail(c.relay, c.box, blob);
    return r.ok;
  }
  // The send connection: no identity, just deliveries (and cover traffic) with answers.
  // It runs on its own random schedule, unrelated to the mail connection, so the relay
  // can't pair the two by when they open and close. On an invite-only relay it proves
  // knowledge of the join code (shared by everyone invited), not which mailbox is ours.
  function runSend() {
    return new Promise(async resolve => {
      let ws, done = false;
      const j = me.join ? await sha('lullwire-join|' + me.join) : undefined;
      const finish = () => {
        if (done) return; done = true; clearInterval(watch); clearTimeout(openTimer);
        if (mail.send === ws) mail.send = null;
        for (const res of mail.reqs.values()) res(null);
        mail.reqs.clear();
        try { ws.close(); } catch {}
        resolve();
      };
      try { ws = new WebSocket(liveURL(me.relay)); } catch { return resolve(); }
      ws.binaryType = 'arraybuffer';
      const openTimer = setTimeout(finish, 12000);
      ws.onopen = () => ws.send(JSON.stringify({ op: 'send', j }));
      ws.onmessage = ev => {
        if (typeof ev.data !== 'string') return;
        let m; try { m = JSON.parse(ev.data); } catch { return; }
        if (m.op === 'ready') { mail.send = ws; clearTimeout(openTimer); }
        else if (m.op === 'error') finish();
        else if (m.op === 'put') { const res = mail.reqs.get(m.r); if (res) { mail.reqs.delete(m.r); res(!!m.ok); } }
      };
      ws.onclose = ws.onerror = finish;
      const watch = setInterval(() => { if (!me || !awake()) finish(); }, 1000);
    });
  }
  async function sendLoop() {
    while (me) {
      if (!awake() || !me.mail || Date.now() <= mail.pollUntil) { await sleep(1000); continue; }
      await sleep(1000 + randInt(20000)); // until then, deliveries go over HTTPS
      if (!me || !awake()) continue;
      await runSend();
      await sleep(2000 + randInt(10000));
    }
  }
  function runSocket() {
    return new Promise(resolve => {
      let ws, ready = false, done = false, chain = Promise.resolve(), acks = [], ackTimer = null, coverTimer = null;
      const finish = how => {
        if (done) return; done = true;
        clearInterval(watch); clearTimeout(openTimer); clearTimeout(coverTimer); clearTimeout(ackTimer);
        if (mail.ws === ws) mail.ws = null;
        if (mail.kick === kick) mail.kick = null;
        if (ready && net.ok) { net.ok = false; net.since = Date.now(); paintNet(); } // reconnecting from here
        try { ws.close(); } catch {}
        resolve(how);
      };
      const kick = () => finish('ok'); mail.kick = kick;
      const url = liveURL(me.relay);
      try { ws = new WebSocket(url); } catch { return resolve('fail'); }
      ws.binaryType = 'arraybuffer';
      const openTimer = setTimeout(() => finish('fail'), 12000);
      const flushAcks = () => { ackTimer = null; if (acks.length && ws.readyState === 1) { ws.send(JSON.stringify({ op: 'ack', ids: acks })); acks = []; } };
      const ack = id => { acks.push(id); if (!ackTimer) ackTimer = setTimeout(flushAcks, 100 + randInt(100)); };
      // Cover traffic out: a delivery-shaped frame at random times, answered like one.
      const cover = () => {
        coverTimer = setTimeout(() => {
          if (mail.send && mail.send.readyState === 1 && me && me.cover) sendFrame(0, rand(16), rand(ENV_MIN + randInt(128))).catch(() => {});
          cover();
        }, 20000 + randInt(70000));
      };
      ws.onopen = () => ws.send(JSON.stringify({ op: 'mail', s: me.secret, cover: !!me.cover }));
      ws.onmessage = ev => {
        if (typeof ev.data !== 'string') return;
        let m; try { m = JSON.parse(ev.data); } catch { return; }
        if (m.op === 'ready') {
          ready = true; mail.ws = ws; mail.fails = 0; clearTimeout(openTimer); cover();
          netUp();
        } else if (m.op === 'error') finish(ready ? 'ok' : 'fail');
        else if (m.op === 'n') ack(hex(rand(11))); // cover traffic in: answered with an ack, like real mail
        else if (m.op === 'm' && typeof m.id === 'string' && typeof m.d === 'string') {
          chain = chain.then(async () => {
            if (done || paused || !me) return; // left on the relay; it comes again on the next connection
            let changed = false;
            try { changed = await receive(fromStd(m.d)); ack(m.id); }
            catch (e) {
              // Undecryptable or forged mail is discarded. A local storage failure leaves it on the
              // relay; reconnecting makes the relay send it again.
              if (STORAGE_ERRORS.includes(e && e.name)) { console.warn('storage error, will retry', e); finish('ok'); return; }
              ack(m.id); console.warn('dropped message', e);
            }
            if (changed) refreshViews();
          });
        }
      };
      ws.onclose = ws.onerror = () => finish(ready ? 'ok' : 'fail');
      const watch = setInterval(() => { if (!me || paused || !awake()) finish('ok'); }, 1000);
    });
  }
  // Long-polling: the relay holds each request open until mail arrives (up to 20s).
  async function pollOnce(wait) {
    // Abortable: wake() drops a request a sleeping phone may have frozen, and the relay
    // answers within wait seconds, so one that takes much longer is dead.
    const ctl = new AbortController(); net.poll = ctl;
    let woken = true;
    const timer = setTimeout(() => { woken = false; ctl.abort(); }, (wait + 15) * 1000);
    try {
      const r = await fetch(me.relay + '?a=get&wait=' + wait, { method: 'POST', headers: TP, body: JSON.stringify({ s: me.secret }), signal: ctl.signal });
      if (r.status === 429) { await sleep(jitter(1000 * (Number(r.headers.get('Retry-After')) || 5))); return true; }
      if (!r.ok) throw new Error(r.status);
      const items = await r.json();
      if (paused || !me) return true; // leave mail on the relay during an account transfer
      const done = [];
      for (const it of items) {
        try { await receive(fromStd(it.d)); done.push(it.id); }
        catch (e) {
          if (STORAGE_ERRORS.includes(e && e.name)) { console.warn('storage error, will retry', e); continue; }
          done.push(it.id); console.warn('dropped message', e);
        }
      }
      if (done.length) {
        await fetch(me.relay + '?a=ack', { method: 'POST', headers: TP, body: JSON.stringify({ s: me.secret, ids: done }) });
        refreshViews();
      }
      netUp();
      return true;
    } catch {
      return ctl.signal.aborted && woken; // dropped on purpose by wake(): start again, nothing failed
    } finally { clearTimeout(timer); if (net.poll === ctl) net.poll = null; }
  }
  async function liveLoop() {
    while (me) {
      if (paused || !awake()) { await nap(1000); continue; }
      if (me.mail && Date.now() > mail.pollUntil) {
        const how = await runSocket();
        if (how === 'ok') { await nap(jitter(800)); continue; }
        // A proxy that doesn't pass WebSockets: fall back to long-polling for a while.
        if (++mail.fails >= 3) { mail.pollUntil = Date.now() + 5 * 60000; mail.fails = 0; }
        await retryLater();
        continue;
      }
      const t0 = Date.now();
      // Varying waits and gaps keep the request rhythm from being a fingerprint.
      if (!(await pollOnce(14 + randInt(7)))) await retryLater();
      const gap = Date.now() - t0;
      const min = 1500 + randInt(800);
      if (gap < min) await sleep(min - gap); // never poll in a tight loop
    }
  }

  // ----- calls -----
  let activeCall = null; // { call, c, id, role, video, ringTimer, startedAt, tick }
  // Frame counters only (no content), used by the automated call test.
  window.__lullwireCallStats = () => activeCall && activeCall.call ? Object.assign({}, activeCall.call.stats) : null;
  function callUI(c, state, incoming) {
    $('#vCall').hidden = false;
    paintAvatar($('#callAvatar'), c.name, c.id);
    $('#callName').textContent = c.name;
    $('#callState').textContent = state;
    $('#callInfo').hidden = false;
    $('#callBarIncoming').hidden = !incoming; $('#callBarActive').hidden = !!incoming;
    const g = $('#remoteCanvas').getContext('2d'); g.fillStyle = '#0d1117'; g.fillRect(0, 0, 9999, 9999);
    $('#callMute').classList.remove('off'); $('#callCam').classList.remove('off');
  }
  function closeCallUI() { $('#vCall').hidden = true; $('#localVideo').hidden = true; if (has('callEnded')) AND.callEnded(); }
  async function startCall(video) {
    const c = contacts.get(current); if (!c || activeCall) return;
    if (!LullwireCall.supported()) return alert('Calls need a newer browser (or the Lullwire Relay Android app).');
    const id = hex(rand(8)), room = hex(rand(32)), key = b64e(rand(32)), live = liveURL(me.relay);
    activeCall = { c, id, role: 'caller', video };
    callUI(c, 'Calling…', false);
    try {
      const call = makeCall({ url: live, room, key, role: 'caller', secret: me.secret, video });
      activeCall.call = call;
      await call.start(); // room is open before they're told about it
      if (!(await post(c, { t: 'call', id, room, key, live, video, ts: Date.now() }))) throw new Error('Could not reach ' + c.name);
      activeCall.ringTimer = setTimeout(() => { if (activeCall && activeCall.id === id && activeCall.call.state !== 'live') endCall('No answer', true); }, 45000);
    } catch (e) { endCall(e.message || 'Call failed', true); }
  }
  function makeCall(opts) {
    return new LullwireCall(Object.assign({ canvas: $('#remoteCanvas'), localVideo: $('#localVideo'), onState: onCallState }, opts));
  }
  function onCallState(state, info) {
    const ac = activeCall; if (!ac) return;
    if (state === 'connecting') $('#callState').textContent = ac.role === 'caller' ? 'Calling…' : 'Connecting…';
    else if (state === 'waiting') $('#callState').textContent = 'Ringing…';
    else if (state === 'live') {
      clearTimeout(ac.ringTimer);
      ac.startedAt = Date.now();
      $('#callBarIncoming').hidden = true; $('#callBarActive').hidden = false;
      const upd = () => { $('#callState').textContent = fmtDur((Date.now() - ac.startedAt) / 1000); };
      upd(); ac.tick = setInterval(upd, 1000);
    } else if (state === 'video') $('#callInfo').hidden = true;
    else if (state === 'remote-av') $('#callInfo').hidden = info.video && ac.call.stats.drawn > 0;
    else if (state === 'ended') {
      const why = info.reason === 'error' ? (info.detail || 'Call failed') : info.reason === 'lost' ? 'Connection lost' : 'Call ended';
      endCall(info.wasLive ? null : why, false);
    }
  }
  async function endCall(reason, tellPeer) {
    const ac = activeCall; if (!ac) return;
    activeCall = null;
    clearTimeout(ac.ringTimer); clearInterval(ac.tick);
    if (tellPeer) post(ac.c, { t: 'call-end', id: ac.id, ts: Date.now() }).catch(() => {});
    if (ac.call && ac.call.state !== 'ended') ac.call.hangup();
    closeCallUI();
    const kind = ac.video ? 'Video call' : 'Voice call';
    await note(ac.c, ac.startedAt ? kind + ' · ' + fmtDur((Date.now() - ac.startedAt) / 1000) : kind + ' · ' + (reason || 'ended'));
    if (reason) toast(reason);
  }
  function onCallMessage(c, msg) {
    const kind = msg.video ? 'video call' : 'voice call';
    if (msg.t === 'call') {
      if (Date.now() - (msg.ts || 0) > 60000) return note(c, 'Missed ' + kind);
      // Only join calls hosted on the caller's own relay, so a message can't send us anywhere else.
      if (c.request) return note(c, 'Missed ' + kind + ' (reply to accept this person first)');
      let ok = false;
      try { ok = msg.live === liveURL(c.relay) && isHex(msg.room, 64) && typeof msg.key === 'string'; } catch {}
      if (!ok) return note(c, 'Ignored a call with an unexpected address');
      if (activeCall || !LullwireCall.supported()) {
        post(c, { t: 'call-decline', id: msg.id, busy: true, ts: Date.now() }).catch(() => {});
        return note(c, 'Missed ' + kind + (activeCall ? ' (you were in another call)' : ' (this browser can\'t do calls)'));
      }
      activeCall = { c, id: msg.id, role: 'callee', video: !!msg.video, incoming: msg };
      callUI(c, 'Incoming ' + kind, true);
      notify('call', c, 'Incoming ' + kind);
      activeCall.ringTimer = setTimeout(() => { if (activeCall && activeCall.id === msg.id && !activeCall.call) endCall('Missed ' + kind, false); }, 45000);
    } else if ((msg.t === 'call-end' || msg.t === 'call-decline') && activeCall && activeCall.id === msg.id && activeCall.c.id === c.id) {
      endCall(msg.t === 'call-decline' ? (msg.busy ? c.name + ' is busy' : 'Declined') : (activeCall.call && activeCall.call.state === 'live' ? null : 'Call ended'), false);
    }
  }
  $('#callAccept').onclick = async () => {
    const ac = activeCall; if (!ac || ac.role !== 'callee' || ac.call) return;
    clearTimeout(ac.ringTimer);
    $('#callBarIncoming').hidden = true; $('#callBarActive').hidden = false;
    $('#callState').textContent = 'Connecting…';
    const m = ac.incoming;
    try { ac.call = makeCall({ url: m.live, room: m.room, key: m.key, role: 'callee', video: ac.video }); await ac.call.start(); }
    catch (e) { endCall(e.message || 'Call failed', true); }
  };
  $('#callDecline').onclick = () => {
    const ac = activeCall; if (!ac) return;
    post(ac.c, { t: 'call-decline', id: ac.id, ts: Date.now() }).catch(() => {});
    endCall('Declined', false);
  };
  $('#callEnd').onclick = () => endCall(null, !(activeCall && activeCall.call && activeCall.call.state === 'live'));
  $('#callMute').onclick = () => { const ac = activeCall; if (!ac || !ac.call) return; const m = !ac.call.muted; ac.call.setMuted(m); $('#callMute').classList.toggle('off', m); };
  $('#callCam').onclick = () => { const ac = activeCall; if (!ac || !ac.call) return; const on = ac.call.camOff; if (ac.call.setCamera(on)) $('#callCam').classList.toggle('off', !on); };
  $('#voiceBtn').onclick = () => startCall(false);
  $('#videoBtn').onclick = () => startCall(true);

  // ----- recovery words -----
  let syncTimer = null;
  function scheduleSync() { if (me && me.rec) { clearTimeout(syncTimer); syncTimer = setTimeout(syncRecovery, 2000); } }
  async function syncRecovery() {
    if (!me || !me.rec) return false;
    try {
      if ([...contacts.values()].filter(c => !c.request).length > BACKUP_CONTACTS) toast('You have more than ' + BACKUP_CONTACTS + ' contacts; only the verified and most recent ones fit in your recovery backup', 6000);
      const d = await sealRecovery(me.rec, await bundle());
      const r = await fetch(me.relay + '?a=rput', { method: 'POST', headers: TP, body: JSON.stringify({ l: me.rec.l, t: me.rec.t, d, s: me.secret }) });
      if (!r.ok) throw new Error('relay answered ' + r.status);
      if (me.recError) { me.recError = null; await saveMe(); }
      return true;
    } catch (e) {
      console.warn('recovery sync failed', e);
      me.recError = String(e.message || e); await saveMe();
      toast('Recovery backup could not be updated — see Settings', 5000);
      return false;
    }
  }
  function renderRecovery() {
    const on = !!(me && me.rec);
    $('#recOn').hidden = !on; $('#recOff').hidden = on; $('#recNew').hidden = true;
    $('#recOld').hidden = !on || me.rec.v === 2;
    $('#recErr').textContent = on && me.recError ? 'Last update failed: ' + me.recError + '. It retries when your contacts change.' : '';
  }
  let draftWords = null;
  const startWords = () => {
    draftWords = genWords();
    $('#recWords').textContent = draftWords;
    $('#recConfirm').value = '';
    $('#recOn').hidden = $('#recOff').hidden = true; $('#recNew').hidden = false;
  };
  $('#recStart').onclick = startWords;
  $('#recUpgrade').onclick = e => { e.preventDefault(); startWords(); };
  $('#recSave').onclick = async () => {
    let typed;
    try { typed = normWords($('#recConfirm').value); } catch (e) { return alert(e.message); }
    if (typed !== draftWords) return alert('Those words don\'t match. Check the order and spelling.');
    toast('Setting up recovery…', 0);
    const rec = await recoveryKeys(draftWords);
    const old = me.rec; me.rec = rec;
    if (!(await syncRecovery())) {
      const why = me.recError || ''; me.rec = old; me.recError = null; toast('');
      return alert(/429/.test(why) ? 'Your relay limits how many new recovery backups can be created per day. Try again tomorrow.'
        : 'Could not save the recovery backup to your relay (' + why + '). Try again.');
    }
    // The new words work; the old slot (older, weaker words) is deleted.
    if (old && old.l !== rec.l) fetch(me.relay + '?a=rdel', { method: 'POST', headers: TP, body: JSON.stringify({ l: old.l, t: old.t }) }).catch(() => {});
    await saveMe(); draftWords = null; toast('Recovery words are on'); renderRecovery();
  };
  $('#recCancel').onclick = () => { draftWords = null; renderRecovery(); };
  $('#recDisable').onclick = async () => {
    if (!confirm('Turn off recovery words? Your backup on the relay will be deleted.')) return;
    try { await fetch(me.relay + '?a=rdel', { method: 'POST', headers: TP, body: JSON.stringify({ l: me.rec.l, t: me.rec.t }) }); } catch {}
    me.rec = null; await saveMe(); renderRecovery();
  };
  $('#recoverBtn').onclick = async () => {
    const relay = $('#relayIn').value.trim() || defaultRelay();
    let rec;
    try { toast('Checking words…', 0); rec = await recoveryKeys($('#recoverWords').value); }
    catch (e) { toast(''); return alert(e.message); }
    try {
      const r = await fetch(relay + '?a=rget', { method: 'POST', headers: TP, body: JSON.stringify({ l: rec.l }) });
      if (r.status === 404) throw new Error('No profile found for those words on this relay. Check the words, and the relay address under "Advanced".');
      if (!r.ok) throw new Error('Relay error ' + r.status);
      const data = await openRecovery(rec, (await r.json()).d);
      data.me.rec = rec;
      await adopt(data);
    } catch (e) { alert(e.message); }
    toast('');
  };

  // ----- moving to a new device -----
  // New device: show a one-time QR holding a fresh public key and a mailbox to drop the profile into.
  let pairing = null;
  $('#pairBtn').onclick = async () => {
    const relay = $('#relayIn').value.trim() || defaultRelay();
    if (!isRelay(relay)) return alert('Relay must be an https:// or .onion address');
    const kp = await genKP(), secret = hex(rand(32)), box = (await sha(secret)).slice(0, 32);
    // The temporary mailbox secret travels in the code so the old phone can admit it on an
    // invite-only relay. It only unlocks a sealed envelope that needs this device's key.
    const url = linkBase(relay) + '#link=' + b64e(enc.encode(JSON.stringify({ r: relay, e: kp.pub, s: secret })));
    const my = pairing = { kp, until: Date.now() + 10 * 60000 };
    show('vPair', 'Move your profile');
    $('#back').hidden = true;
    $('#pairLink').value = url;
    $('#pairCode').textContent = await linkCode(kp.pub);
    renderQR($('#pairQR'), url);
    while (pairing === my && Date.now() < my.until) {
      try {
        const r = await fetch(relay + '?a=get&wait=20', { method: 'POST', headers: TP, body: JSON.stringify({ s: secret }) });
        if (!r.ok) { await sleep(3000); continue; }
        for (const it of await r.json()) {
          let bundle;
          try { bundle = await openOuter(kp, fromStd(it.d)); } catch { continue; }
          if (pairing !== my || !bundle || bundle.t !== 'link') continue;
          const who = bundle.data && bundle.data.me ? String(bundle.data.me.name || '?').slice(0, 40) : '?';
          const n = bundle.data && Array.isArray(bundle.data.contacts) ? bundle.data.contacts.length : 0;
          if (!confirm('Sign in as "' + who + '" with ' + n + ' contact(s)? Only continue if this is your own profile.')) continue;
          pairing = null;
          fetch(relay + '?a=ack', { method: 'POST', headers: TP, body: JSON.stringify({ s: secret, ids: [it.id] }) }).catch(() => {});
          try { await adopt(bundle.data); }
          catch (e) { alert('Could not sign in: ' + e.message); show('vSetup'); return; }
          if (bundle.ack && isRelay(bundle.ack.r) && isBox(bundle.ack.b))
            // The acknowledgement carries the secret nonce from the sealed bundle, so a relay can't fake it.
            postMail(bundle.ack.r, bundle.ack.b,
              isHex(bundle.ack.n, 64) ? new Uint8Array([...hexBytes(bundle.ack.n), ...rand(64)]) : rand(96)).catch(() => {});
          return;
        }
      } catch { await sleep(3000); }
    }
    if (pairing === my) { pairing = null; alert('This move code expired. Start again.'); show('vSetup'); }
  };
  $('#pairCancel').onclick = () => { pairing = null; show('vSetup'); };
  $('#pairCopy').onclick = async () => { try { await copyText($('#pairLink').value); toast('Copied'); } catch { $('#pairLink').select(); } };

  // Old device: approve, send the profile, wait for the new device to confirm, then sign out.
  let pendingLink = null;
  async function showLinkRequest(text) {
    const o = parseHashData(text, 'link');
    if (o && isHex(o.s, 64)) o.b = (await sha(o.s)).slice(0, 32); // the mailbox follows from its secret
    if (!o || !isRelay(o.r) || !isBox(o.b) || typeof o.e !== 'string') throw new Error('That move code is damaged');
    await importPub(o.e);
    pendingLink = o;
    show('vLink', 'Move your profile');
    $('#linkCode').textContent = await linkCode(o.e);
  }
  $('#linkCancel').onclick = () => { pendingLink = null; goHome(); };
  $('#linkApprove').onclick = async () => {
    const o = pendingLink; if (!o) return;
    pendingLink = null; paused = true;
    $('#linkApprove').disabled = true; toast('Sending your profile…', 0);
    const ackSecret = hex(rand(32)), ackBox = (await sha(ackSecret)).slice(0, 32);
    try {
      if (me.join) { // invite-only relays: admit the two temporary mailboxes used for the move
        const join = (relay, s) => fetch(relay + '?a=join', { method: 'POST', headers: TP, body: JSON.stringify({ s, code: me.join }) }).catch(() => {});
        await join(me.relay, ackSecret);
        // Your join code only ever goes to your own relay, never to one named in a scanned code.
        if (isHex(o.s, 64) && new URL(o.r).host === new URL(me.relay).host) await join(o.r, o.s);
      }
      const ackNonce = hex(rand(32));
      const sealed = { t: 'link', data: await bundle(), ack: { r: me.relay, b: ackBox, n: ackNonce } };
      const r = await postMail(o.r, o.b, await sealOuter(sealed, o.e));
      if (!r.ok) throw new Error('the relay refused it (' + r.status + ')');
      toast('Waiting for the new device to confirm…', 0);
      const until = Date.now() + 120000;
      while (Date.now() < until) {
        const g = await fetch(me.relay + '?a=get&wait=20', { method: 'POST', headers: TP, body: JSON.stringify({ s: ackSecret }) });
        const items = g.ok ? await g.json() : [];
        if (items.length) {
          await fetch(me.relay + '?a=ack', { method: 'POST', headers: TP, body: JSON.stringify({ s: ackSecret, ids: items.map(i => i.id) }) }).catch(() => {});
          // Erase this device only for the real acknowledgement (it holds the nonce that
          // travelled sealed to the new device), never just because something arrived.
          const real = items.some(i => { try { return hex(fromStd(i.d).slice(0, 32)) === ackNonce; } catch { return false; } });
          if (real) return wipe('Your profile moved to the new device. This device is now signed out.');
        }
        if (!g.ok) await sleep(2000);
      }
      throw new Error('the new device did not confirm');
    } catch (e) {
      paused = false; toast(''); $('#linkApprove').disabled = false;
      alert('Move not confirmed: ' + e.message + '. This device stays signed in. If the new device signed in anyway, erase one of them.');
      goHome();
    }
  };

  // Take over a profile bundle (move, recovery words or backup file).
  async function adopt(data) {
    const r = await restoreData(data);
    await saveIdentity(r.me.jwk); delete r.me.jwk;
    me = r.me;
    if (!me.inviteTok) me.inviteTok = b64e(rand(12));
    const info = await relayInfo(me.relay); me.calls = info.calls; me.mail = info.mail;
    if (has('setBackground')) me.bg = true;
    await saveMe();
    for (const x of r.contacts) {
      if (!isBox(x.box) || !isRelay(x.relay)) continue;
      try { await importPub(x.pub); } catch { continue; }
      const c = newContact(await contactId(x.pub), x.pub, x.box, x.relay, x.name);
      c.verified = !!x.verified; c.blocked = !!x.blocked;
      c.floor = Date.now(); // opening messages from before this copy of the profile are replays
      contacts.set(c.id, c); await saveContact(c);
    }
    start();
    // Ratchet state never travels; tell each contact to switch to a fresh session.
    for (const c of contacts.values()) if (!c.blocked) post(c, { t: 'reset', id: hex(rand(8)), ts: Date.now() }).catch(() => {});
  }
  function wipe(msg) {
    me = null; vk = null; mkRaw = null;
    if (db) db.close();
    if (has('vaultForget')) AND.vaultForget();
    if (has('setBackground')) AND.setBackground(false);
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = req.onerror = req.onblocked = () => {
      const old = indexedDB.deleteDatabase('hush2');
      old.onsuccess = old.onerror = old.onblocked = () => { if (msg) alert(msg); location.replace(location.pathname); };
    };
  }

  // ----- invite / add / settings -----
  async function openInvite() {
    show('vInvite', 'Invite');
    const link = await inviteLink();
    $('#inviteLink').value = link;
    renderQR($('#inviteQR'), link);
  }
  $('#inviteBtn').onclick = openInvite;
  $('#settingsInviteBtn').onclick = openInvite;
  $('#newInviteBtn').onclick = async e => {
    e.preventDefault();
    if (!confirm('Make a new invite link? People who use your old link will arrive as requests instead of contacts.')) return;
    me.inviteTok = b64e(rand(12)); me.inviteUses = 0; await saveMe(); scheduleSync();
    openInvite(); toast('New invite link ready');
  };
  $('#copyBtn').onclick = async () => { try { await copyText($('#inviteLink').value); toast('Invite link copied'); } catch { $('#inviteLink').select(); } };
  $('#shareBtn').onclick = () => AND ? AND.share('Here\'s my private chat invite: ' + $('#inviteLink').value) : navigator.share
    ? navigator.share({ title: 'Chat with me on Lullwire Relay', text: 'Here\'s my private chat invite:', url: $('#inviteLink').value }).catch(() => {})
    : $('#copyBtn').click();
  $('#addLinkBtn').onclick = () => { show('vAdd', 'Add a contact'); $('#addIn').value = ''; };
  $('#addBtn').onclick = () => {
    const v = $('#addIn').value.trim(); if (!v) return;
    // A pasted move code could come from anyone ("paste this to add me"): moves only start from Scan.
    if (/#link=/.test(v)) return alert('That is a request to move a profile, not an invite. To move your profile, use Scan on the device that has it.');
    handleCode(v);
  };
  $('#addScanBtn').onclick = openScanner;
  $('#scanBtn').onclick = openScanner;
  $('#settingsScanBtn').onclick = openScanner;
  $('#back').onclick = () => { if (!$('#vSafety').hidden && current) return openChat(current); goHome(); };
  $('#scanFile').onchange = async e => {
    const f = e.target.files[0]; e.target.value = ''; if (!f) return;
    try {
      const bmp = await createImageBitmap(f);
      const t = await decodeQR(bmp, bmp.width, bmp.height);
      if (!t) return alert('No code found in that picture');
      stopScanner(); handleCode(t);
    } catch { alert('Could not read that picture'); }
  };
  $('#scanCancel').onclick = goHome;
  const vaultLabel = () => vaultHdr.mode === 'pass' ? 'Encrypted, locked with your passphrase'
    : vaultHdr.mode === 'android' ? 'Encrypted with a key in Android\'s secure storage' : 'Encrypted (key kept by this browser; add an app lock for more)';
  function renderSettings() {
    paintAvatar($('#meAvatar'), me.name, me.pub);
    $('#meName').textContent = me.name;
    $('#myRelay').textContent = me.relay;
    $('#myCalls').textContent = me.calls ? 'Available' : 'Not supported by this relay';
    $('#myDelivery').textContent = mail.ws ? 'Live connection' : me.mail ? 'Live connection (reconnecting)' : 'Long-polling (this relay has no live connection)';
    $('#myJoin').textContent = me.join || 'None (open relay)';
    $('#myVault').textContent = vaultLabel();
    $('#myBuild').textContent = window.__lullwireBuild ? window.__lullwireBuild() : 'Version ' + $('#appVer').textContent;
    $('#lockOn').hidden = vaultHdr.mode !== 'pass'; $('#lockOff').hidden = vaultHdr.mode === 'pass';
    $('#coverWrap').hidden = !me.mail; $('#coverIn').checked = !!me.cover;
    $('#bgWrap').hidden = $('#namesWrap').hidden = !has('setBackground');
    $('#bgIn').checked = me.bg !== false; $('#namesIn').checked = !!me.notifyNames;
    renderRecovery();
  }
  $('#settingsBtn').onclick = async () => {
    show('vSettings', 'Settings');
    $('#myFp').textContent = (await contactId(me.pub)).slice(0, 16).match(/.{4}/g).join(' ');
    renderSettings();
  };
  $('#coverIn').onchange = async e => { me.cover = e.target.checked; await saveMe(); if (mail.ws) mail.ws.close(); };
  $('#bgIn').onchange = async e => { me.bg = e.target.checked; await saveMe(); AND.setBackground(me.bg); };
  $('#namesIn').onchange = async e => { me.notifyNames = e.target.checked; await saveMe(); };
  $('#saveJoinBtn').onclick = async () => {
    const code = $('#newJoinIn').value.trim(); if (!code) return;
    const r = await fetch(me.relay + '?a=join', { method: 'POST', headers: TP, body: JSON.stringify({ s: me.secret, code }) }).catch(() => null);
    if (!r || !r.ok) return alert(r && r.status === 403 ? 'That join code was not accepted.' : 'Could not reach your relay.');
    me.join = code; await saveMe(); $('#myJoin').textContent = code; $('#newJoinIn').value = ''; toast('Join code saved');
  };
  $('#exportBtn').onclick = async () => {
    const p1 = $('#bp1').value, p2 = $('#bp2').value;
    if (p1.length < 12) return alert('Use a passphrase of at least 12 characters');
    if (p1 !== p2) return alert('Passphrases don\'t match');
    toast('Encrypting backup…', 0);
    try {
      const text = await exportBackup({ ...me, jwk: await identityJwk() }, [...contacts.values()], p1);
      const fname = 'lullwire-backup-' + new Date().toISOString().slice(0, 10) + '.lullwire';
      if (AND) { AND.saveFile(fname, text); $('#bp1').value = $('#bp2').value = ''; toast(''); return; }
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
      a.download = fname;
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
      $('#bp1').value = $('#bp2').value = '';
      toast('Backup downloaded');
    } catch (e) { toast(''); alert('Backup failed: ' + e.message); }
  };
  $('#wipeBtn').onclick = () => {
    if (confirm('Erase your identity, contacts and messages from this device? Without recovery words or a backup this cannot be undone.')) wipe();
  };
  $('#attachBtn').onclick = () => $('#fileIn').click();
  $('#fileIn').onchange = e => { const f = e.target.files[0]; e.target.value = ''; if (f) sendFile(f); };
  // For the automated tests: the files in the open chat, with a hash of what is stored.
  window.__lullwireFiles = async () => {
    const out = [];
    for (const m of (await messagesFor(current, 1000)).list) if (m.file) {
      const b = m.dir === 'out' || m.state === 'done' ? await fileBytes(m.file) : null;
      out.push({ dir: m.dir, name: m.file.name, size: m.file.size, state: m.state, sha: b ? await sha(b) : null });
    }
    return out;
  };
  $('#composer').onsubmit = e => { e.preventDefault(); const t = $('#txt').value; $('#txt').value = ''; $('#txt').style.height = ''; send(t); };
  $('#txt').onkeydown = e => { if (e.key === 'Enter' && !e.shiftKey && !/Android|Mobi/.test(navigator.userAgent)) { e.preventDefault(); $('#composer').requestSubmit(); } };
  $('#txt').oninput = e => { const t = e.target; t.style.height = ''; t.style.height = Math.min(t.scrollHeight, 140) + 'px'; };

  // ----- app lock (vault master secret wrapped with a passphrase) -----
  // Without a passphrase the master secret is wrapped by the Android Keystore (in the
  // app) or kept as-is (a browser has no safer place for it).
  async function defaultHeader(mk) {
    if (has('vaultWrap')) {
      const w = AND.vaultWrap(b64e(mk));
      if (w) return { v: 1, mode: 'android', w };
      console.warn('Android Keystore unavailable; the vault key is stored without it (Settings shows this)');
    }
    return { v: 1, mode: 'plain', mk };
  }
  async function unwrapHeader(hdr) {
    if (hdr.mode === 'plain') return u8(hdr.mk);
    if (hdr.mode === 'android') {
      const raw = has('vaultUnwrap') ? AND.vaultUnwrap(hdr.w) : '';
      if (!raw) throw new Error('This device\'s secure storage could not open the app data.');
      return b64d(raw);
    }
    throw new Error('locked');
  }
  const setHeader = async hdr => { await tx('meta', 'readwrite', s => s.put(hdr, 'vault')); vaultHdr = hdr; };
  $('#lockOnBtn').onclick = async () => {
    const p1 = $('#lp1').value, p2 = $('#lp2').value;
    if (p1.length < 8) return alert('Use a passphrase of at least 8 characters');
    if (p1 !== p2) return alert('Passphrases don\'t match');
    toast('Locking…', 0);
    const mk = rand(32);
    await rekeyVault({ v: 1, mode: 'pass', ...(await wrapWithPass(mk, p1)) }, mk);
    if (has('vaultForget')) AND.vaultForget();
    $('#lp1').value = $('#lp2').value = ''; toast('App lock is on'); renderSettings();
  };
  $('#lockOffBtn').onclick = async () => {
    const p = prompt('Enter your passphrase to turn off the app lock'); if (p === null) return;
    try { await unwrapWithPass(vaultHdr, p); } catch { return alert('That passphrase is not right.'); }
    await setHeader(await defaultHeader(mkRaw)); toast('App lock is off'); renderSettings();
  };
  $('#lockNowBtn').onclick = () => { if (has('setBackground')) AND.setBackground(false); location.reload(); };
  $('#lockWipe').onclick = e => {
    e.preventDefault();
    if (confirm('Erase everything on this device? You can recover your profile with your recovery words, but messages stored here are lost.')) wipe();
  };
  function unlockScreen() {
    return new Promise(resolve => {
      show('vLock', 'Lullwire Relay');
      $('#unlockIn').value = ''; $('#unlockIn').focus();
      $('#unlockForm').onsubmit = async e => {
        e.preventDefault();
        $('#unlockBtn').disabled = true; toast('Unlocking…', 0);
        try { const mk = await unwrapWithPass(vaultHdr, $('#unlockIn').value); toast(''); resolve(mk); }
        catch { toast(''); alert('That passphrase is not right.'); $('#unlockIn').select(); }
        finally { $('#unlockBtn').disabled = false; }
      };
    });
  }

  // ----- sign up -----
  let setupInfo = null;
  async function prepareSetup() {
    const relay = $('#relayIn').value.trim() || defaultRelay();
    setupInfo = await relayInfo(relay);
    const fromInvite = pendingInvite && pendingInvite.j;
    $('#joinWrap').hidden = !setupInfo.invite || !!fromInvite;
    if (fromInvite) $('#joinIn').value = pendingInvite.j;
    document.body.dataset.setup = 'ready';
  }
  $('#relayIn').onchange = prepareSetup;
  // Opened from an invite (or pasted one) before having a profile: create one, then
  // the inviter is added automatically. With no relay of our own yet, use theirs.
  function setupInvite(text) {
    try {
      const o = readInvite(text);
      pendingInvite = Object.assign({ raw: text }, o);
      paintAvatar($('#invitedAvatar'), o.n, o.p);
      $('#invitedName').textContent = String(o.n || 'Someone').slice(0, 40);
      $('#invitedBy').hidden = false; $('#pasteInviteWrap').hidden = true;
      if (!$('#relayIn').value.trim() && isRelay(o.r)) $('#relayIn').value = o.r;
      return true;
    } catch { return false; }
  }
  $('#pasteInviteIn').oninput = () => {
    const t = $('#pasteInviteIn').value.trim();
    if (/#i=/.test(t)) { if (setupInvite(t)) prepareSetup(); else toast('That invite link looks damaged'); }
  };
  // The Android app hands over links shared to it or opened with it.
  window.lullwireOpen = text => {
    text = String(text || '');
    if (me) return openFromOutside(text);
    if (/#i=/.test(text) && setupInvite(text)) prepareSetup();
    else if (/#link=/.test(text)) alert('This is a request to move a profile onto a new device. Open it (or scan it) on the device that already has your profile.');
  };
  $('#createBtn').onclick = async () => {
    const name = $('#nameIn').value.trim(), relay = $('#relayIn').value.trim();
    if (!name) return alert('Enter your name');
    if (!isRelay(relay)) return alert('Relay must be an https:// or .onion address');
    $('#createBtn').disabled = true;
    try {
      const info = await relayInfo(relay);
      if (!info.ok && !confirm('That relay didn\'t answer like a Lullwire relay. Use it anyway?')) return;
      const draft = await newIdentity(name, relay);
      if (info.invite) {
        const code = $('#joinIn').value.trim();
        if (!code) { $('#joinWrap').hidden = false; return alert('This relay is invite-only. Enter its join code, or open an invite link from someone who uses it.'); }
        const r = await fetch(relay + '?a=join', { method: 'POST', headers: TP, body: JSON.stringify({ s: draft.secret, code }) });
        if (r.status === 403) { $('#joinWrap').hidden = false; return alert('That join code was not accepted.'); }
        if (!r.ok) return alert('Could not join the relay (' + r.status + '). Try again.');
        draft.join = code;
      }
      draft.calls = info.calls; draft.mail = info.mail;
      draft.inviteTok = b64e(rand(12));
      if (has('setBackground')) draft.bg = true;
      await saveIdentity(draft.jwk); delete draft.jwk;
      me = draft;
      await saveMe();
      start();
      if (pendingInvite) {
        const inv = pendingInvite; pendingInvite = null;
        try { const c = await addFromInvite(inv.raw); openChat(c.id); } catch (e) { alert(e.message); }
      }
    } finally { $('#createBtn').disabled = false; }
  };
  $('#restoreBtn').onclick = async () => {
    const f = $('#restoreFile').files[0], pass = $('#restorePass').value;
    if (!f || !pass) return alert('Choose a backup file and enter its passphrase');
    toast('Decrypting backup…', 0);
    let data;
    try { data = await openBackup(await f.text(), pass); }
    catch { toast(''); return alert('Could not open the backup: wrong passphrase or damaged file'); }
    try { await adopt(data); } catch (e) { alert(e.message); }
    toast('');
  };

  async function handleHash() {
    const h = location.hash;
    if (!/^#(i|link)=/.test(h)) return;
    history.replaceState(null, '', location.pathname);
    openFromOutside(h);
  }
  // A link opened from outside (a web page, another app, a shared text) is never
  // trusted like a code you scanned yourself: move requests are refused outright
  // (they hand over your whole profile), and invites are added only if you say so.
  async function openFromOutside(text) {
    if (/#link=/.test(text)) return alert('To move your profile, open Scan in the app and scan the code shown on the new device.');
    if (!/#i=/.test(text)) return;
    let o; try { o = readInvite(text); } catch (e) { return alert(e.message); }
    const name = String(o.n || 'Someone').slice(0, 40);
    if (o.p === me.pub) return;
    const known = [...contacts.values()].find(c => c.pub === o.p);
    if (known) return openChat(known.id);
    if (!confirm('Add ' + name + ' as a contact? They will be able to message and call you.')) return;
    handleCode(text);
  }

  // ----- which code is running -----
  // The service worker checks app code against the release key; it tells us what it runs.
  let build = AND ? { android: true } : { none: true };
  window.__lullwireBuild = () => build.android ? 'Built into this app (signed APK)'
    : build.none ? 'Loaded straight from the server (not verified)'
    : !build.signed ? 'Unsigned build'
    : 'Version ' + build.version + ', signed release (key ' + build.key.match(/.{4}/g).join(' ') + ')' +
      (build.next ? '; ' + build.next + ' is ready for the next start' : '') +
      (build.warn ? '. Refused an update from the server: ' + build.warn : '');
  function watchServiceWorker() {
    if (!('serviceWorker' in navigator) || AND) return;
    navigator.serviceWorker.register('sw.js').catch(() => {});
    navigator.serviceWorker.addEventListener('message', e => {
      const d = e.data || {};
      if (d.t === 'lullwire-status') build = d;
      else if (d.t === 'lullwire-update') { build.next = d.version; toast('Lullwire Relay ' + d.version + ' is ready. It starts the next time you open the app.', 6000); }
      else if (d.t === 'lullwire-refused') { build.warn = d.why; toast('The server offered app code that isn\'t signed by the developer. You\'re still on the verified version (see Settings).', 9000); }
    });
    const ask = () => navigator.serviceWorker.controller && navigator.serviceWorker.controller.postMessage({ q: 'status' });
    navigator.serviceWorker.ready.then(ask);
    navigator.serviceWorker.addEventListener('controllerchange', ask);
  }
  // Delivery path, for tests and Settings.
  window.__lullwireDelivery = () => mail.ws ? (mail.send ? 'socket' : 'socket (receiving)') : 'poll';

  async function keepPrekeysFresh() { if (me && await rotatePrekeys(me)) await saveMe(); }
  function start() {
    goHome(); handleHash();
    if (started) return; started = true;
    // Invite-only relays expire memberships nobody renews; renew ours quietly on every start.
    if (me.join) fetch(me.relay + '?a=join', { method: 'POST', headers: TP, body: JSON.stringify({ s: me.secret, code: me.join }) }).catch(() => {});
    if (has('setBackground')) AND.setBackground(me.bg !== false);
    keepPrekeysFresh(); setInterval(keepPrekeysFresh, 6 * 3600000);
    // Learn what the relay supports (live connection, calls) before choosing how to receive.
    relayInfo(me.relay).then(async info => {
      if (info.ok && (info.calls !== !!me.calls || info.mail !== !!me.mail)) { me.calls = info.calls; me.mail = info.mail; await saveMe(); }
    }).catch(() => {}).finally(() => { liveLoop(); sendLoop(); });
    // After an update from 0.5, sessions were renewed: tell each contact.
    for (const c of contacts.values()) if (c.needReset) {
      c.needReset = false; saveContact(c);
      if (!c.blocked) post(c, { t: 'reset', why: 'upgrade', id: hex(rand(8)), ts: Date.now() }).catch(() => {});
    }
  }

  // LEGACY(0.5): move the plaintext "hush2" store into the vault. Ratchet keys of 0.5
  // can't be exported, so sessions restart (contacts get a "reset"). The move can be
  // interrupted (the page closed, storage full): a "migrating" flag stays set until it has
  // completed, every start before then redoes it from scratch, and "hush2" is deleted
  // only after a complete move.
  async function migrateLegacy(old) {
    const get = (store, fn) => txOn(old, store, 'readonly', fn);
    const oldMe = await get('kv', s => s.get('me'));
    if (!oldMe || !oldMe.priv) { await tx('meta', 'readwrite', s => s.delete('migrating')); old.close(); return false; }
    await tx('meta', 'readwrite', s => s.put(true, 'migrating'));
    await new Promise((res, rej) => { // start clean: drop anything a previous, interrupted attempt wrote
      const t = db.transaction(['kv', 'contacts', 'messages'], 'readwrite');
      for (const n of ['kv', 'contacts', 'messages']) t.objectStore(n).clear();
      t.oncomplete = res; t.onerror = () => rej(t.error);
    });
    blinds.clear();
    const jwk = await crypto.subtle.exportKey('jwk', oldMe.priv);
    const { priv, ...rest } = oldMe;
    const m = { ...rest, ...(await keysFromJwk(jwk)), spks: [] };
    await rotatePrekeys(m);
    await saveIdentity(jwk);
    me = m; await saveMe();
    for (const c of (await get('contacts', s => s.getAll())) || []) {
      c.sessions = {}; c.active = null; c.opened = null; c.needReset = true;
      await saveContact(c);
    }
    const msgs = ((await get('messages', s => s.getAll())) || []).sort((a, b) => a.id - b.id);
    for (const x of msgs) { const { id, ...m2 } = x; await putMessage(m2); }
    await tx('meta', 'readwrite', s => s.delete('migrating'));
    old.close();
    indexedDB.deleteDatabase('hush2');
    console.info('moved ' + msgs.length + ' messages from the 0.5 store into the encrypted vault');
    return true;
  }

  async function migrateOrExplain(legacy) {
    try { await migrateLegacy(legacy); return true; }
    catch (e) {
      console.warn('moving the 0.5 data failed', e);
      show('vLock'); $('#unlockForm').hidden = true;
      $('#vLock h2').textContent = 'Couldn\'t finish updating your data';
      $('#vLock .hero p').textContent = 'Your chats from the older version are safe and nothing was deleted. ' +
        (e && e.name === 'QuotaExceededError' ? 'This device is out of storage space: free some up, then reopen the app.' : 'Reopen the app to try again (' + (e && e.message || e) + ').');
      return false;
    }
  }

  // App lock on: a new master secret, and every record re-encrypted with it, all in one
  // transaction with the new header, so copies of the old (unlocked) files are no help.
  // Waits until no contact work and no queued write is in progress.
  async function settle() {
    for (let i = 0; i < 50; i++) {
      const busy = [...locks.values(), ...writeQ.values()];
      await Promise.all(busy);
      await sleep(50);
      if ([...locks.values(), ...writeQ.values()].every(p => busy.includes(p))) return;
    }
  }
  async function rekeyVault(header, newMk) {
    // Nothing may be written with the old key after we read: stop receiving, let work finish.
    const was = paused; paused = true;
    try {
      if (mail.ws) mail.ws.close();
      await settle();
      await rekeyNow(header, newMk);
    } finally { paused = was; }
  }
  async function rekeyNow(header, newMk) {
    const nk = await vaultKeys(newMk), nb = new Map();
    const blindNew = async id => { let x = nb.get(id); if (!x) { x = await blindId(nk, id); nb.set(id, x); } return x; };
    let keys, kvs, cs, ms; // one read transaction, so keys and records belong together
    await new Promise((res, rej) => {
      const t = db.transaction(['kv', 'contacts', 'messages'], 'readonly');
      t.objectStore('kv').getAllKeys().onsuccess = e => { keys = e.target.result; };
      t.objectStore('kv').getAll().onsuccess = e => { kvs = e.target.result; };
      t.objectStore('contacts').getAll().onsuccess = e => { cs = e.target.result; };
      t.objectStore('messages').getAll().onsuccess = e => { ms = e.target.result; };
      t.oncomplete = res; t.onerror = () => rej(t.error);
    });
    const kvOut = [], cOut = [], mOut = [], byBlind = new Map();
    for (let i = 0; i < keys.length; i++) kvOut.push([keys[i], { d: await sealRecord(nk, 'kv|' + keys[i], await openRecord(vk, 'kv|' + keys[i], kvs[i].d)) }]);
    for (const r of cs) {
      const c = await openRecord(vk, 'contacts|' + r.id, r.d), id = await blindNew(c.id);
      byBlind.set(r.id, id);
      cOut.push({ old: r.id, rec: { id, d: await sealRecord(nk, 'contacts|' + id, c) } });
    }
    for (const r of ms) {
      const c = byBlind.get(r.c); if (!c) continue; // messages of deleted contacts are dropped
      mOut.push({ id: r.id, c, d: await sealRecord(nk, 'messages|' + c, await openRecord(vk, 'messages|' + r.c, r.d)) });
    }
    await new Promise((res, rej) => {
      const t = db.transaction(['meta', 'kv', 'contacts', 'messages'], 'readwrite');
      const k = t.objectStore('kv'), c = t.objectStore('contacts'), m = t.objectStore('messages');
      for (const [key, v] of kvOut) k.put(v, key);
      for (const x of cOut) { c.delete(x.old); c.put(x.rec); }
      for (const x of mOut) m.put(x);
      t.objectStore('meta').put(header, 'vault');
      t.oncomplete = res; t.onerror = () => rej(t.error); t.onabort = () => rej(t.error);
    });
    vaultHdr = header; mkRaw = newMk; vk = nk; blinds.clear();
    for (const [id, b] of nb) blinds.set(id, b);
  }

  (async () => {
    // Refuse to run inside another site's frame (clickjacking).
    if (window.top !== window.self) { document.body.textContent = 'Lullwire Relay cannot run inside another page.'; return; }
    // IPFS path gateways (gateway.example/ipfs/<cid>/) put every IPFS site on one origin,
    // so any of them could read this app's storage. Only run on an origin of our own.
    if (/^\/(ipfs|ipns)\//.test(location.pathname)) {
      document.body.textContent = 'Open Lullwire Relay from its own domain or a subdomain gateway (https://<cid>.ipfs.dweb.link/). ' +
        'Path-style IPFS gateways share storage with every other IPFS site, which would expose your keys.';
      return;
    }
    if (!window.isSecureContext || !crypto.subtle) { document.body.textContent = 'Lullwire Relay needs a secure (https) connection.'; return; }
    watchServiceWorker();
    db = await openVaultDB();
    vaultHdr = await tx('meta', 'readonly', s => s.get('vault'));
    const legacy = await openLegacyDB();
    if (!vaultHdr) {
      const mk = rand(32);
      if (legacy) await tx('meta', 'readwrite', s => s.put(true, 'migrating')); // before the header, so a restart resumes
      await setHeader(await defaultHeader(mk));
      await useVault(mk);
      if (legacy && !(await migrateOrExplain(legacy))) return;
    } else {
      let mk;
      try { mk = vaultHdr.mode === 'pass' ? await unlockScreen() : await unwrapHeader(vaultHdr); }
      catch (e) {
        show('vLock'); $('#unlockForm').hidden = true;
        $('#vLock h2').textContent = 'Can\'t open the app data'; $('#vLock .hero p').textContent = e.message;
        return;
      }
      $('#unlockForm').hidden = false;
      await useVault(mk);
      if (legacy && await tx('meta', 'readonly', s => s.get('migrating'))) { if (!(await migrateOrExplain(legacy))) return; } // finish an interrupted move
      else if (legacy) { legacy.close(); indexedDB.deleteDatabase('hush2'); } // left over from a completed move
      if (!me) me = await loadMe();
    }
    for (const c of await loadContacts()) contacts.set(c.id, c);
    document.body.dataset.ready = '1';
    if (me) {
      if (!me.inviteTok) { me.inviteTok = b64e(rand(12)); await saveMe(); }
      return start();
    }
    $('#relayIn').value = defaultRelay();
    show('vSetup');
    if (/^#i=/.test(location.hash)) {
      setupInvite(location.hash);
      history.replaceState(null, '', location.pathname);
    } else if (/^#link=/.test(location.hash)) {
      history.replaceState(null, '', location.pathname);
      alert('This is a request to move a profile onto a new device. Open it (or scan it) on the device that already has your profile.');
    }
    if (!$('#relayIn').value.trim()) $('#relayIn').closest('details').open = true;
    prepareSetup();
    $('#nameIn').focus();
  })();
})();
