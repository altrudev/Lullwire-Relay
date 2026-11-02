// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
// Lullwire Relay 0.6 talks to Hush Relay 0.5: the frozen 0.5 crypto core (tests/fixtures/app-0.5.js) and the
// current one exchange messages, backups and recovery bundles in both directions.
// LEGACY(v2): remove together with the v2 code paths.
const path = require('path');
const N = require(path.join(__dirname, '..', 'web', 'app.js'));
const O = require(path.join(__dirname, 'fixtures', 'app-0.5.js'));
const R = 'https://relay.example.org/relay.php';
let fails = 0, n = 0; const ok = (c, m) => { n++; console.log((c ? '  ok   ' : '  FAIL ') + m); if (!c) fails++; };
const view = p => ({ pub: p, sessions: {}, active: null });
const rejects = async p => { try { await p; return false; } catch { return true; } };
(async () => {
  const neu = await N.newIdentity('New', R), old = await O.newIdentity('Old', R);
  const nO = view(old.pub), oN = view(neu.pub);
  // New -> old: v2 envelope (the new app doesn't know the old one speaks v4), card attached.
  const m1 = await N.encryptFor(neu, nO, { t: 'msg', txt: 'hi old', ts: Date.now() });
  const i1 = await O.openOuter(old, m1);
  ok(i1.v === 2 && i1.q && (await O.decryptFrom(old, oN, i1)).txt === 'hi old', 'new app -> 0.5 app');
  // Old -> new: 0.5 envelope, sealed to the identity key, no card.
  const m2 = await O.encryptFor(old, oN, { t: 'msg', txt: 'hi new', ts: Date.now() });
  const i2 = await N.openOuter(neu, m2);
  ok((await N.decryptFrom(neu, nO, i2)).txt === 'hi new' && !nO.v4, '0.5 app -> new app (stays v2)');
  for (let i = 0; i < 3; i++) {
    const a = await N.openOuter(neu, await O.encryptFor(old, oN, { t: 'msg', txt: 'o' + i, ts: Date.now() }));
    await N.decryptFrom(neu, nO, a);
    const b = await O.openOuter(old, await N.encryptFor(neu, nO, { t: 'msg', txt: 'n' + i, ts: Date.now() }));
    await O.decryptFrom(old, oN, b);
  }
  ok(nO.active === oN.active, 'a mixed conversation stays on one session');
  // Backups made by 0.5 restore in 0.6 (and get a prekey and signing key).
  const bk = await O.exportBackup(old, [{ pub: neu.pub, box: neu.box, relay: R, name: 'New' }], 'correct horse battery');
  const r = await N.importBackup(bk, 'correct horse battery');
  ok(r.me.pub === old.pub && r.me.spks.length === 1 && await N.checkCard(r.me.pub, r.me.box, r.me.relay, await N.makeCard(r.me)), '0.5 backup file restores in 0.6');
  // 6-word recovery words from 0.5 open the same slot in 0.6.
  const w = O.genWords(), ko = await O.recoveryKeys(w), kn = await N.recoveryKeys(w);
  ok(ko.l === kn.l && ko.t === kn.t && ko.k === kn.k && kn.v === 1, '0.5 recovery words derive the same slot');
  const slot = await O.sealRecovery(ko, await O.backupData(old, []));
  ok((await N.restoreData(await N.openRecovery(kn, slot))).me.pub === old.pub, '0.5 recovery slot opens in 0.6');
  // Lullwire writes its own backup format; Hush Relay can't read it (a clear error, not garbage).
  const nb = await N.exportBackup(neu, [], 'correct horse battery');
  ok(/^LULLWIRE1\./.test(nb) && await rejects(O.importBackup(nb, 'correct horse battery')) && (await N.importBackup(nb, 'correct horse battery')).me.pub === neu.pub, 'Lullwire backup format (LULLWIRE1) round-trips');
  ok(await rejects(O.openOuter(old, await N.sealOuter({ x: 1 }, neu.spks[0].pub))), 'sanity: other keys do not open');
  console.log(fails ? fails + ' of ' + n + ' FAILED' : 'all ' + n + ' passed'); process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
