// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
// Device test, run by tests/android/run.sh: Alice uses the Android app, Bob uses a
// second browser on the same emulator (Android's WebView shell), side by side.
// Invite link, messages both ways, and an encrypted video call answered in the app.
const connect = require('./cdp');
const RELAY = process.env.RELAY || 'http://localhost:8099/relay';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const has = (sel, t) => `[...document.querySelectorAll(${JSON.stringify(sel)})].some(e => e.textContent.includes(${JSON.stringify(t)}))`;
const timer = `/^\\d+:\\d\\d$/.test(document.querySelector('#callState').textContent)`;
(async () => {
  const A = await connect(9333), B = await connect(9334);
  console.log('app:', await A.ev('return navigator.userAgent.match(/LullwireAndroid\\S*( debug)?/)[0]'));
  await A.load('https://appassets.androidplatform.net/index.html'); await A.waitFor(`document.body.dataset.setup === 'ready'`);
  await A.fill('#relayIn', RELAY); await A.fill('#nameIn', 'Alice'); await A.tap('#createBtn');
  await A.waitVisible('#vList', 30000);
  await A.click('#inviteBtn'); await A.waitFor(`document.querySelector('#inviteQR').naturalWidth > 0`);
  const link = await A.value('#inviteLink');
  console.log('1 Alice made a profile in the app; invite points at the relay:', link.startsWith(RELAY.replace(/[^/]*$/, '') + '#i='));
  await B.load(link); await B.waitVisible('#invitedBy', 30000); await B.waitFor(`document.body.dataset.setup === 'ready'`);
  await B.fill('#nameIn', 'Bob'); await B.click('#createBtn'); await B.waitVisible('#vChat', 30000);
  console.log('2 Bob joined from the invite in a browser');
  await B.fill('#txt', 'Hi Alice'); await B.ev(`document.querySelector('#composer').requestSubmit()`);
  await A.click('#back'); await A.waitFor(has('.contact', 'Bob'), 30000);
  await A.ev(`[...document.querySelectorAll('.contact')].find(e => e.textContent.includes('Bob')).click()`);
  await A.waitFor(has('.m.in', 'Hi Alice'), 30000);
  await A.fill('#txt', 'Hello from the app'); await A.ev(`document.querySelector('#composer').requestSubmit()`);
  await B.waitFor(has('.m.in', 'from the app'), 30000);
  console.log('3 messages both ways: OK');
  await B.click('#videoBtn');
  await A.waitVisible('#callBarIncoming', 30000);
  console.log('4 the app is ringing:', await A.text('#callState'));
  await A.tap('#callAccept');
  await A.waitFor(timer, 40000); await B.waitFor(timer, 20000);
  await sleep(10000);
  const st = { app: await A.ev('return window.__lullwireCallStats()'), browser: await B.ev('return window.__lullwireCallStats()') };
  console.log('  call stats:', JSON.stringify(st));
  const ok = Object.values(st).every(s => s.recvAudio > 100 && s.recvVideo > 20 && s.drawn > 20 && s.bad === 0);
  console.log('  audio and video both ways, nothing failed to decrypt:', ok);
  await A.click('#callEnd'); await B.waitFor(`document.querySelector('#vCall').hidden`, 15000);
  console.log('5 hang-up from the app reached the browser:', await B.ev(`return [...document.querySelectorAll('.m.sys')].map(e => e.textContent).pop()`));
  // 6. Background mode (on by default in the app): pressed Home, the app keeps its connection,
  // receives, and shows a notification without names.
  const adb = (...a) => require('child_process').execFileSync(process.env.ADB, ['-s', process.env.SERIAL, ...a]).toString();
  adb('shell', 'input', 'keyevent', 'HOME'); await sleep(4000);
  await B.fill('#txt', 'Are you there?'); await B.ev(`document.querySelector('#composer').requestSubmit()`);
  await A.waitFor(has('.m.in', 'Are you there'), 30000).catch(() => {});
  const got = await A.ev(`return ${has('.m.in', 'Are you there')}`);
  const notes = adb('shell', 'dumpsys', 'notification', '--noredact');
  const bg = got && /Connected to your relay/.test(notes) && /New message/.test(notes);
  console.log('6 app in the background received the message:', got, '| connection and message notifications:', bg);
  const errs = A.errors.map(e => 'app: ' + e).concat(B.errors.map(e => 'browser: ' + e)).filter(e => !/400 \(Bad Request\)/.test(e));
  console.log('errors:', errs.length ? errs : 'none');
  process.exit(ok && bg && !errs.length ? 0 : 1);
})().catch(e => { console.log('FAILED', e.message); process.exit(1); });
