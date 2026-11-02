// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
// Lullwire Relay test suite: crypto core + relay HTTP API.
// Run via tests/run.sh (starts a throwaway relay), or:
//   RELAY=http://127.0.0.1:8099/relay.php node tests/core.test.js
const path=require('path');
const H=require(path.join(__dirname,'..','web','app.js'));
// The app stamps every message with an authenticated time; tests do the same.
const encRaw=H.encryptFor, encryptFor=(me,c,m)=>encRaw(me,c,{ts:Date.now(),...m});
const R=process.env.RELAY||'http://127.0.0.1:8099/relay.php';
let fails=0, n=0; const ok=(c,m)=>{n++;console.log((c?'  ok   ':'  FAIL ')+m); if(!c) fails++;};
const view=p=>({pub:p,sessions:{},active:null});
const post=(a,b,q='')=>fetch(R+'?a='+a+q,{method:'POST',body:typeof b==='string'||b instanceof Uint8Array?b:JSON.stringify(b)});
async function recv(me,book,blob){const inner=await H.openOuter(me,blob); const c=book[inner.f]||(book[inner.f]=view(inner.f)); return {msg:await H.decryptFrom(me,c,inner),inner};}
const rejects=async p=>{try{await p;return false}catch{return true}};
async function ratchet(){

 const A=await H.newIdentity('Alice',R), B=await H.newIdentity('Bob',R), E=await H.newIdentity('Eve',R);
 const aB=view(B.pub); const bBook={}, aBook={[B.pub]:aB};
 // 1. first contact + reply
 let x=await recv(B,bBook,await encryptFor(A,aB,{t:'msg',txt:'hi'})); ok(x.msg.txt==='hi'&&x.inner.n==='Alice','first message');
 const bA=bBook[A.pub];
 x=await recv(A,aBook,await encryptFor(B,bA,{txt:'yo'})); ok(x.msg.txt==='yo','reply');
 // 2. out-of-order within and across ratchet steps
 const m=[]; for(let i=0;i<5;i++) m.push(await encryptFor(A,aB,{txt:'a'+i}));
 const got=[]; for(const i of [3,0,4,2,1]) got.push((await recv(B,bBook,m[i])).msg.txt);
 ok(got.join()==='a3,a0,a4,a2,a1','out-of-order delivery');
 // 3. replay rejected
 ok(await rejects(recv(B,bBook,m[2])),'replay rejected');
 // 4. many alternating turns
 let good=true; for(let i=0;i<20;i++){ const s=i%2?[B,bA,A,aBook]:[A,aB,B,bBook]; const r=await recv(s[2],s[3],await encryptFor(s[0],s[1],{txt:'t'+i})); if(r.msg.txt!=='t'+i) good=false; } ok(good,'20 alternating turns');
 // 5. forward secrecy: snapshot Bob's state, then an old message cannot be decrypted with current state
 const old=await encryptFor(A,aB,{txt:'secret'}); await recv(B,bBook,old);
 ok(await rejects(recv(B,bBook,old)),'consumed key is gone');
 // 6. forged sender: Eve claims to be Alice
 const fake=await encryptFor(E,view(B.pub),{txt:'evil'}); const fi=await H.openOuter(B,fake); fi.f=A.pub;
 const bA2=bBook[A.pub]; const before=JSON.stringify(Object.keys(bA2.sessions));
 ok(await rejects(H.decryptFrom(B,bA2,fi)),'forged sender rejected');
 ok(JSON.stringify(Object.keys(bA2.sessions))===before,'forgery did not touch state');
 // 7. tamper
 const t=await encryptFor(A,aB,{txt:'z'}); t[120]^=1; ok(await rejects(recv(B,bBook,t)),'tamper rejected');
 // 8. simultaneous first messages (fresh pair)
 const C=await H.newIdentity('Cat',R), D=await H.newIdentity('Dan',R);
 const cD=view(D.pub), dC=view(C.pub), cBook={[D.pub]:cD}, dBook={[C.pub]:dC};
 const c1=await encryptFor(C,cD,{txt:'c1'}), d1=await encryptFor(D,dC,{txt:'d1'});
 const r1=(await recv(D,dBook,c1)).msg.txt, r2=(await recv(C,cBook,d1)).msg.txt;
 const r3=(await recv(D,dBook,await encryptFor(C,cD,{txt:'c2'}))).msg.txt, r4=(await recv(C,cBook,await encryptFor(D,dC,{txt:'d2'}))).msg.txt;
 ok([r1,r2,r3,r4].join()==='c1,d1,c2,d2','simultaneous start converges');
 // 9. padding hides length
 const sizes=[]; for(const t of ['x','x'.repeat(150),'y','z'.repeat(100)]) sizes.push((await encryptFor(A,aB,{txt:t})).length);
 ok(sizes.every(n=>n>=1024+93&&n<1024+128+93),'padded to one size class ('+sizes.join(', ')+')');
 // 10. backup round trip + reset
 const bk=await H.exportBackup(A,[{pub:B.pub,box:B.box,relay:R,name:'Bob',verified:true}],'correct horse battery');
 ok(await rejects(H.importBackup(bk,'wrong passphrase!!')),'wrong passphrase rejected');
 const RA=await H.importBackup(bk,'correct horse battery'); ok(RA.me.pub===A.pub&&RA.contacts[0].verified,'backup restores identity');
 const raB=view(B.pub); const rs=await recv(B,bBook,await encryptFor(RA.me,raB,{t:'reset'})); ok(rs.msg.t==='reset','reset after restore');
 x=await recv(RA.me,{[B.pub]:raB},await encryptFor(B,bBook[A.pub],{txt:'welcome back'})); ok(x.msg.txt==='welcome back','restored device receives');
 // 11. real relay round trip
 await fetch(R+'?a=put&box='+B.box,{method:'POST',body:await encryptFor(A,aB,{txt:'via relay'})});
 const items=await (await fetch(R+'?a=get',{method:'POST',body:JSON.stringify({s:B.secret})})).json();
 ok((await recv(B,bBook,Uint8Array.from(atob(items[0].d),c=>c.charCodeAt(0)))).msg.txt==='via relay','relay round trip');
 }
async function relayAndRecovery(){

 const A=await H.newIdentity('Alice',R), B=await H.newIdentity('Bob',R);
 const aB=view(B.pub), bBook={};
 // ratchet regression
 const m=[]; for(let i=0;i<4;i++) m.push(await encryptFor(A,aB,{txt:'a'+i}));
 const got=[]; for(const i of [2,0,3,1]) got.push((await recv(B,bBook,m[i])).msg.txt); ok(got.join()==='a2,a0,a3,a1','ratchet still works out of order');
 ok(await rejects(recv(B,bBook,m[1])),'replay rejected');
 // long-poll: request waits, then returns as soon as mail lands
 const t0=Date.now(); const lp=post('get',{s:B.secret},'&wait=10');
 setTimeout(async()=>post('put',await encryptFor(A,aB,{txt:'live!'}),'&box='+B.box),1500);
 const items=await (await lp).json(); const dt=Date.now()-t0;
 ok(items.length===1 && dt>1300 && dt<4000,'long-poll returned on arrival after '+dt+'ms');
 ok((await recv(B,bBook,Uint8Array.from(atob(items[0].d),c=>c.charCodeAt(0)))).msg.txt==='live!','live message decrypts');
 await post('ack',{s:B.secret,ids:items.map(i=>i.id)});
 const t1=Date.now(); const empty=await (await post('get',{s:B.secret},'&wait=2')).json(); ok(empty.length===0 && Date.now()-t1>=1900,'empty long-poll waits then returns []');
 // recovery words
 const w=H.genWords(); ok(w.split(' ').length===8,'8 words: '+w);
 ok(H.normWords(w.toUpperCase().replace(/ /g,', '))===w,'normalizes case/punctuation');
 ok(H.normWords(w.split(' ').map(x=>x.slice(0,4)).join(' '))===w,'accepts 4-letter prefixes');
 ok(await rejects((async()=>H.normWords('apple banana zzzz qqqq able about'))()),'rejects unknown word');
 const rec=await H.recoveryKeys(w), rec2=await H.recoveryKeys(w); ok(rec.l===rec2.l&&rec.k===rec2.k,'keys deterministic');
 const d=await H.sealRecovery(rec,await H.backupData(A,[{pub:B.pub,box:B.box,relay:R,name:'Bob'}]));
 ok((await post('rput',{l:rec.l,t:rec.t,d})).ok,'rput stores');
 ok((await post('rput',{l:rec.l,t:'0'.repeat(64),d})).status===403,'overwrite with wrong token refused');
 const back=await (await post('rget',{l:rec.l})).json();
 const restored=await H.restoreData(await H.openRecovery(await H.recoveryKeys(w),back.d)); ok(restored.me.pub===A.pub&&restored.contacts[0].name==='Bob','recovered from words');
 const other=await H.recoveryKeys(H.genWords()); ok((await post('rget',{l:other.l})).status===404,'other words find nothing');
 ok(await rejects(H.openRecovery(other,back.d)),'wrong key cannot open');
 ok((await post('rdel',{l:rec.l,t:rec.t})).ok && (await post('rget',{l:rec.l})).status===404,'rdel removes slot');
 // link bundle
 const eph=await H.genKP(); const bundle={t:'link',data:await H.backupData(A,[])};
 const opened=await H.openOuter(eph,await H.sealOuter(bundle,eph.pub)); ok((await H.restoreData(opened.data)).me.pub===A.pub,'link bundle opens on new device');
 ok((await H.linkCode(eph.pub)).match(/^\d{4} \d{4} \d{4}$/),'link code format');
 const forged=await H.backupData(A,[]); forged.me.pub=B.pub; ok(await rejects(H.restoreData(forged)),'mismatched key bundle rejected');
 // backup file still works
 const bf=await H.exportBackup(A,[],'correct horse battery'); ok((await H.importBackup(bf,'correct horse battery')).me.pub===A.pub,'backup file round trip');
 }
async function auditRegressions(){
  const A=await H.newIdentity('Alice',R), B=await H.newIdentity('Bob',R);
  // Finding 2: replaying an old opening message after its session was dropped must fail.
  const aB=view(B.pub), bBook={};
  const first=await encryptFor(A,aB,{t:'msg',txt:'hello',ts:Date.now()});
  await recv(B,bBook,first);
  const bA=bBook[A.pub]; const sid=Object.keys(bA.sessions)[0];
  delete bA.sessions[sid]; bA.active=null;               // e.g. pruned or after a reset
  ok(await rejects(recv(B,bBook,first)),'replayed opening message refused after session is gone');
  // ...and on a restored copy, opening messages from before the backup are refused.
  const restored={pub:A.pub,sessions:{},active:null,floor:Date.now()+60*60000};
  const restoredBook={[A.pub]:restored};
  ok(await rejects(recv(B,restoredBook,await encryptFor(A,view(B.pub),{t:'msg',txt:'old',ts:Date.now()}))),'stale opening message refused after restore');
  // Re-review 2: a contact's new device with a slow clock still takes over the conversation.
  const P=await H.newIdentity('Pat',R); const pB=view(B.pub), bBook3={};
  await recv(B,bBook3,await encryptFor(P,pB,{t:'msg',txt:'hi'}));
  await recv(P,{[B.pub]:pB},await encryptFor(B,bBook3[P.pub],{t:'msg',txt:'hey'}));     // established
  const moved=view(B.pub);                                                           // Pat's new device: no sessions
  const r1=await recv(B,bBook3,await encRaw(P,moved,{t:'reset',id:'r',ts:Date.now()-3*60000}));
  ok(bBook3[P.pub].active===r1.inner.s && bBook3[P.pub].opened===r1.inner.s,'reset from a slow-clock device becomes the active session');
  const back=await recv(P,{[B.pub]:moved},await encryptFor(B,bBook3[P.pub],{t:'msg',txt:'welcome'}));
  ok(back.msg.txt==='welcome','replies reach the moved device');
  // Simultaneous first messages converge on the same session.
  const X=await H.newIdentity('X',R), Y=await H.newIdentity('Y',R); const xY=view(Y.pub), yX=view(X.pub);
  const fx=await encryptFor(X,xY,{t:'msg',txt:'x'}), fy=await encryptFor(Y,yX,{t:'msg',txt:'y'});
  await recv(Y,{[X.pub]:yX},fx); await recv(X,{[Y.pub]:xY},fy);
  ok(xY.active===yX.active,'simultaneous starts converge on one session');
  for(let i=0;i<3;i++){ await recv(Y,{[X.pub]:yX},await encryptFor(X,xY,{t:'msg',txt:'a'+i})); await recv(X,{[Y.pub]:xY},await encryptFor(Y,yX,{t:'msg',txt:'b'+i})); }
  ok(xY.active===yX.active,'...and stay converged over several rounds');
  const C=await H.newIdentity('Cat',R);
  // Re-review 4: a far-future timestamp cannot freeze a contact.
  const Z=await H.newIdentity('Z',R); const bBook4={};
  await recv(B,bBook4,await encRaw(Z,view(B.pub),{t:'msg',txt:'future',ts:Date.now()+365*864e5}));
  ok(bBook4[Z.pub].lastTs<=Date.now()+11*60000,'future timestamps are clamped');
  // Messages without an authenticated timestamp are refused.
  ok(await rejects(recv(B,{},await encRaw(A,view(B.pub),{t:'msg',txt:'no ts'}))),'message without timestamp refused');
  // Finding 3 and 5: relay address validation.
  ok(H.isRelay('https://relay.example.com/relay.php'),'normal https relay accepted');
  ok(!H.isRelay('https://x.example/'+'a'.repeat(300)),'over-long relay refused');
  ok(!H.isRelay('http://localhost:@evil.com/relay.php'),'credential trick refused');
  ok(!H.isRelay('https://user:pw@evil.com/relay.php'),'credentials refused');
  ok(!H.isRelay('javascript:alert(1)'),'non-http scheme refused');
  const onion='http://'+'abcdefghijklmnopqrstuvwxyz234567'.repeat(2).slice(0,56)+'.onion/relay.php';
  ok(H.isRelay(onion),'v3 onion relay accepted over http');
  ok(!H.isRelay('http://short.onion/relay.php'),'malformed onion refused');
  ok(!H.isRelay('http://'+'a'.repeat(56)+'.onion.evil.com/relay.php'),'onion look-alike refused');
  ok(!H.isRelay('http://evil.com/relay.php'),'plain http refused');
  // Unanswered requests stay out of the recovery bundle.
  const bundle=await H.backupData(A,[{pub:B.pub,box:B.box,relay:R,name:'Bob'},{pub:C.pub,box:C.box,relay:R,name:'spam',request:true}]);
  ok(bundle.contacts.length===1,'message requests left out of backups');
  // Finding 13: bundles must be internally consistent.
  const bad=await H.backupData(A,[]); bad.me.box='0'.repeat(32);
  ok(await rejects(H.restoreData(bad)),'bundle with mismatched mailbox refused');
  // Finding 9: link code is 12 digits.
  ok(/^\d{4} \d{4} \d{4}$/.test(await H.linkCode(A.pub)),'12-digit link code');
  // Finding 6: array parameters are a clean 400, not a crash.
  ok((await fetch(R+'?a=put&box[]=1',{method:'POST',body:new Uint8Array(100)})).status===400,'array box parameter gives 400');
  ok((await fetch(R+'?a[]=get',{method:'POST',body:'{}'})).status===400,'array action parameter gives 400');
  // Finding 10: an unused mailbox does not hold a worker for the full wait.
  const t0=Date.now(); await (await post('get',{s:H.hex(H.rand(32))},'&wait=20')).json();
  ok(Date.now()-t0<5000,'empty mailbox long-poll capped ('+(Date.now()-t0)+'ms)');
  // Finding 4: too-small envelopes refused.
  ok((await post('put',new Uint8Array(80),'&box='+B.box)).status===413,'undersized envelope refused');
  // (live-connection limits are tested with parallel curl in tests/run.sh)

  // A large contact list still fits the recovery slot and link transfer.
  // Worst case: as many contacts as a backup keeps, every relay address at the 256-character maximum.
  const many=[]; for(let i=0;i<H.BACKUP_CONTACTS+50;i++){const k=await H.genKP(); const base='https://relay-'+i+'.example.org/'; many.push({pub:k.pub,box:H.hex(H.rand(16)),relay:base+'a'.repeat(256-base.length),name:'Contact number '+String(i).padEnd(25,'x')});}
  many[many.length-1].verified=true; many[0].blocked=true;
  const big=await H.backupData(A,many); const rec=await H.recoveryKeys(H.genWords());
  ok(big.contacts.length===H.BACKUP_CONTACTS && big.contacts[0].verified && !big.contacts.some(c=>c.blocked),'backup keeps verified contacts first when there are too many');
  const d=await H.sealRecovery(rec,big);
  ok((await post('rput',{l:rec.l,t:rec.t,d})).ok,'largest account: recovery backup stored ('+Math.round(d.length/1024)+' KB)');
  const eph=await H.genKP(); const sealed=await H.sealOuter({t:'link',data:big},eph.pub);
  ok((await post('put',sealed,'&box='+B.box)).ok,'largest account: transfer accepted ('+Math.round(sealed.length/1024)+' KB)');
}
async function protocolV4(){
  const A=await H.newIdentity('Alice',R), B=await H.newIdentity('Bob',R), E=await H.newIdentity('Eve',R);
  // Cards: signed by the identity key, bound to mailbox, relay, prekey and time.
  const qB=await H.makeCard(B);
  ok(await H.checkCard(B.pub,B.box,B.relay,qB),'own card verifies');
  ok(!(await H.checkCard(B.pub,E.box,B.relay,qB)),'card with a swapped mailbox refused');
  ok(!(await H.checkCard(B.pub,B.box,'https://evil.example/relay.php',qB)),'card with a swapped relay refused');
  ok(!(await H.checkCard(B.pub,B.box,B.relay,{...qB,s:E.spks[0].pub})),'card with a swapped prekey refused');
  ok(!(await H.checkCard(B.pub,E.box,E.relay,await H.makeCard(E))),"someone else's card refused");
  ok(!(await H.checkCard(B.pub,B.box,B.relay,{...qB,t:Date.now()+3*864e5})),'card from the far future refused');
  // Alice learns Bob's card (from his invite): sessions open against his prekey.
  const aB=view(B.pub); ok(await H.takeCard(aB,B.box,B.relay,qB) && aB.v4,'card taken from an invite');
  ok(!(await H.takeCard(aB,B.box,B.relay,qB)),'same card not taken twice');
  const first=await encryptFor(A,aB,{t:'msg',txt:'v4 hello'});
  const onlyId={...B,spks:[]};
  ok(await rejects(H.openOuter(onlyId,first)),'outer layer sealed to the prekey: the identity key alone cannot open it');
  const fi=await H.openOuter(B,first);
  ok(fi.v===4 && fi.h.e && fi.h.sp===B.spks[0].pub && fi.q,'opening message is v4, names the prekey, carries a card');
  const bBook={}; const r1=await recv(B,bBook,first); ok(r1.msg.txt==='v4 hello','v4 opening decrypts');
  const bA=bBook[A.pub]; ok(await H.takeCard(bA,fi.b,fi.r,fi.q) && bA.v4,'card taken from a message');
  const back=await recv(A,{[B.pub]:aB},await encryptFor(B,bA,{t:'msg',txt:'v4 reply'}));
  ok(back.msg.txt==='v4 reply' && back.inner.v===4,'v4 reply decrypts');
  const next=await H.openOuter(A,await encryptFor(B,bA,{t:'msg',txt:'later'}));
  ok(next.h.e===undefined,'answered sessions stop repeating the opening keys');
  ok(back.inner.qa===A.spks[0].t && aB.qAck===A.spks[0].t,'Bob confirms he holds Alice\'s card');
  await recv(B,bBook,await encryptFor(A,aB,{t:'msg',txt:'ack mine'}));
  const after=await H.openOuter(B,await encryptFor(A,aB,{t:'msg',txt:'no card'}));
  ok(after.q===undefined && after.qa===qB.t && bA.qAck===qB.t,'a confirmed card is not resent; each side confirms the other\'s');
  // Sender binding: every field of the inner envelope is authenticated by the ratchet.
  for(const [f,val] of [['b',E.box],['r','https://evil.example/relay.php'],['n','Mallory'],['q',await H.makeCard(E)]]){
    const m=await H.openOuter(B,await encryptFor(A,aB,{t:'msg',txt:'bind'}));
    const snap=JSON.stringify(Object.keys(bA.sessions)); m[f]=val;
    ok(await rejects(H.decryptFrom(B,bA,m)) && JSON.stringify(Object.keys(bA.sessions))===snap,'changed sender field "'+f+'" is refused');
  }
  // Forward secrecy for opening messages: once the prekey is gone, a stolen identity key
  // (with every later prekey) can't read a recorded opening message.
  const C=await H.newIdentity('Cat',R); const cB=view(B.pub); await H.takeCard(cB,B.box,B.relay,qB);
  const recorded=await encryptFor(C,cB,{t:'msg',txt:'recorded'});
  const later={...B,spks:[...B.spks]}; await H.rotatePrekeys(later,Date.now()+H.SPK_KEEP+864e5);
  ok(!later.spks.some(k=>k.pub===qB.s) && later.spks.length===1,'prekeys rotate and old ones are forgotten');
  ok(await rejects(recv(later,{},recorded)),'recorded opening message unreadable after its prekey is deleted');
  // A prekey too old to rely on is not used: the session opens the v2 way, sealed to the identity.
  const old=view(B.pub); old.card={...qB,b:B.box,r:B.relay,t:Date.now()-H.SPK_USE-864e5}; old.v4=true;
  const o2=await H.openOuter(onlyId,await encryptFor(A,old,{t:'msg',txt:'old card'}));
  ok(o2.h.e===undefined,'stale prekey not used');
  // Rotation timing.
  const D=await H.newIdentity('Dan',R); const k0=D.spks[0].pub;
  ok(!(await H.rotatePrekeys(D,Date.now()+H.SPK_ROTATE-864e5)) && await H.rotatePrekeys(D,Date.now()+H.SPK_ROTATE+1000) && D.spks.length===2 && D.spks[1].pub===k0,'a new prekey every 14 days, the old one kept');
  // An unknown prekey (deleted, or made up) can't open a session.
  const fakeCard=view(B.pub); fakeCard.card={s:(await H.genKP()).pub,t:Date.now(),b:B.box,r:R}; fakeCard.v4=true;
  ok(await rejects(recv(B,{},await encryptFor(A,fakeCard,{t:'msg',txt:'?'}))),'message sealed to an unknown prekey refused');
  ok(await rejects(H.decryptFrom(B,view(A.pub),{v:4,s:'x',c:'AA',h:{dh:A.pub,pn:0,n:0,e:A.pub,sp:fakeCard.card.s}})),'opening that names an unknown prekey refused');
  // Review 2026-11-02 #8: session ids have a fixed shape (no 30 MB ids stored by strangers).
  const big=await H.openOuter(B,await encryptFor(A,view(B.pub),{t:'msg',txt:'x'})); big.s='A'.repeat(100000);
  ok(await rejects(H.decryptFrom(B,view(A.pub),big)),'over-long session id refused');
  // Review #7: after a contact restores (no card of ours), our card is sent again.
  const Al=await H.newIdentity('Al',R), Bo=await H.newIdentity('Bo',R);
  const alBo=view(Bo.pub); await H.takeCard(alBo,Bo.box,Bo.relay,await H.makeCard(Bo));
  const boBook={}; await recv(Bo,boBook,await encryptFor(Al,alBo,{t:'msg',txt:'1'}));
  await H.takeCard(boBook[Al.pub],Al.box,Al.relay,(await H.openOuter(Bo,await encryptFor(Al,alBo,{t:'msg',txt:'2'}))).q||await H.makeCard(Al));
  await recv(Al,{[Bo.pub]:alBo},await encryptFor(Bo,boBook[Al.pub],{t:'msg',txt:'3'}));
  ok(alBo.qAck===Al.spks[0].t,'card confirmed before the restore');
  const restored=view(Al.pub); // Bo on a new device: knows Al's key, not Al's card
  await recv(Al,{[Bo.pub]:alBo},await encryptFor(Bo,restored,{t:'reset',id:'r'}));
  const again=await H.openOuter(Bo,await encryptFor(Al,alBo,{t:'msg',txt:'4'}));
  ok(alBo.qAck===undefined && again.q && again.q.t===Al.spks[0].t,'card sent again to a contact that no longer holds it');
  // Signed invites: a mailbox swapped in an intercepted invite no longer verifies.
  const inv={p:B.pub,b:B.box,r:B.relay,q:qB};
  ok(await H.checkCard(inv.p,inv.b,inv.r,inv.q) && !(await H.checkCard(inv.p,E.box,inv.r,inv.q)),'invite card detects a swapped mailbox');
}
async function recoveryAndVault(){
  const A=await H.newIdentity('Alice',R);
  const w=H.genWords(); ok(w.split(' ').length===8,'8 recovery words: '+w);
  const k2=await H.recoveryKeys(w); ok(k2.v===2,'8 words use recovery v2');
  const w6=w.split(' ').slice(0,6).join(' '); const k1=await H.recoveryKeys(w6);
  ok(k1.v===1 && k1.l!==k2.l,'6 words still work (v1) and map to a different slot');
  ok(await rejects((async()=>H.normWords(w.split(' ').slice(0,7).join(' ')))()),'7 words refused');
  const d=await H.sealRecovery(k2,await H.backupData(A,[]));
  ok((H.b64d(d).length-28)%16384===0,'recovery slot padded ('+H.b64d(d).length+' bytes)');
  const back=await H.restoreData(await H.openRecovery(k2,d));
  ok(back.me.pub===A.pub && back.me.spks.length===1 && back.me.sign,'recovered identity gets a fresh prekey and a signing key');
  ok(await H.checkCard(back.me.pub,back.me.box,back.me.relay,await H.makeCard(back.me)),'recovered identity signs valid cards');
  // Runtime identity keys are not extractable.
  ok(await rejects(crypto.subtle.exportKey('jwk',A.priv)) && await rejects(crypto.subtle.exportKey('jwk',A.sign)),'identity keys are non-extractable at runtime');
  // Padding: random tails stay inside their size class; big payloads are padded too.
  const ps=[...Array(20)].map(()=>H.pad('x').length); ok(Math.min(...ps)>=1024 && Math.max(...ps)<1152 && new Set(ps).size>1,'padding tail varies within the class');
  ok(H.pad('x'.repeat(40000)).length===49152,'large payloads padded to 16 KiB steps');
  // Vault: records with ratchet state round-trip; tampering, moving or the wrong key fail.
  const mk=H.rand(32), vk=await H.vaultKeys(mk), vk2=await H.vaultKeys(H.rand(32));
  const B=await H.newIdentity('Bob',R); const aB=view(B.pub); await H.takeCard(aB,B.box,B.relay,await H.makeCard(B));
  await encryptFor(A,aB,{t:'msg',txt:'a'});
  const sealed=await H.sealRecord(vk,'contacts|x',aB), opened=await H.openRecord(vk,'contacts|x',sealed);
  const st=opened.sessions[opened.active];
  ok(st.RK instanceof Uint8Array && st.DHs.priv instanceof CryptoKey && opened.card.s===aB.card.s,'contact record round-trips with its ratchet state');
  const bBook={}; await recv(B,bBook,await encryptFor(A,opened,{t:'msg',txt:'b'})); // B never saw 'a': skipped, still fine
  ok(true,'restored ratchet state keeps sending');
  ok(await rejects(H.openRecord(vk,'contacts|y',sealed)),'record moved to another key refused');
  ok(await rejects(H.openRecord(vk2,'contacts|x',sealed)),'other vault key refused');
  const t2=Uint8Array.from(sealed); t2[30]^=1; ok(await rejects(H.openRecord(vk,'contacts|x',t2)),'tampered record refused');
  ok((await H.blindId(vk,'abc'))===(await H.blindId(vk,'abc')) && (await H.blindId(vk,'abc'))!==(await H.blindId(vk2,'abc')),'blinded ids are stable per vault');
  const wp=await H.wrapWithPass(mk,'correct horse battery');
  ok(H.hex(await H.unwrapWithPass(wp,'correct horse battery'))===H.hex(mk) && await rejects(H.unwrapWithPass(wp,'wrong horse battery')),'passphrase wraps the vault key');
}
(async()=>{
  console.log('Ratchet and envelope'); await ratchet();
  console.log('Relay, live mode, recovery, linking'); await relayAndRecovery();
  console.log('Audit regressions'); await auditRegressions();
  console.log('Protocol v4: prekeys, cards, sender binding'); await protocolV4();
  console.log('Recovery v2, padding, vault'); await recoveryAndVault();
  console.log(fails?fails+' of '+n+' FAILED':'all '+n+' passed'); process.exit(fails?1:0);
})().catch(e=>{console.error(e);process.exit(1)});
