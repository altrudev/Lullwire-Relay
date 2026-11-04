# Lullwire Relay protocol (v4)

All cryptography uses the browser's WebCrypto API: ECDH and ECDSA on P-256, HKDF-SHA-256, HMAC-SHA-256, AES-256-GCM and PBKDF2-SHA-256. Encodings are base64url without padding unless noted.

Labels beginning with `hush/` or `hush-` are the historical names from Hush Relay 0.5 (this project's old name). They are part of the wire format that 0.5 apps speak, so they keep their spelling; everything introduced in 0.6 uses `lullwire/`.

## Identity and mailbox

- **Identity key:** a P-256 key pair generated on the device. The public key (65-byte raw) is the identity. The same key does ECDH (sessions, sealed envelopes) and ECDSA-SHA-256 signatures (prekeys and address cards), the way Signal's XEdDSA reuses its identity key. At runtime the app holds it only as two non-extractable WebCrypto keys; the private JWK lives in the encrypted vault (below).
- **Mailbox:** `secret` = 32 random bytes as hex, and `box` = first 32 hex characters of `SHA-256(secret)`. Anyone may deliver to `box`; reading and deleting require `secret`, which is only ever sent in a POST body or over the live connection.
- **Contact id:** the first 32 hex characters of `SHA-256(rawPub)`. A different key is a different contact.
- **Safety number:** `SHA-256(pubA ‖ pubB)` with the two keys sorted. The first 40 hex characters are shown in groups of 5. Because the identity key signs everything else, comparing it once covers prekeys and address changes too.

## Signed prekeys and address cards

- **Signed prekey (SPK):** a P-256 ECDH key pair. A new one is made every 14 days; each is kept for 45 days and then deleted. Senders use a prekey only while its card is less than 28 days old (the remaining 17 days cover mail waiting on a relay for up to 14 days, plus clock skew).
- **Card:** `q = {s: spkPub, t: spkCreatedMs, g: sig}`, where `sig = ECDSA(identity, "lullwire/v4/card|" + pub + "|" + box + "|" + relay + "|" + s + "|" + t)`. It binds the mailbox, the relay address and the prekey to the identity. Relay addresses may not contain `|`, so the encoding is unambiguous. A card is accepted only with a valid signature, a `t` no more than a day in the future, and a `t` newer than the card already held. A newer valid card moves a contact to the mailbox and relay it names.
- Cards travel in invites and inside messages. A message carries the sender's card until the recipient confirms holding it: v4 messages include `qa`, the `t` of the recipient's card that the sender holds, and the recipient stops attaching its card once `qa` matches. A message without `qa` (v2, or a contact's fresh copy after a restore) means "send it again".
- Cards are not stored in backups or recovery slots (size); contacts send theirs again after a restore.

## Invite

`https://<app>/#i=` followed by `base64url(JSON {p: pub, b: box, r: relayURL, n: name, k: inviteToken, q: card, j?: joinCode})`. It travels in the URL fragment, so it never reaches a server.

- `q` signs `b` and `r`: an invite whose card doesn't verify is refused (someone changed it). An invite without a card (from Hush Relay 0.5) is added only after a warning. For a contact you already have, a newer signed card moves them without a question; an unsigned one asks first.
- `k` is 12 random bytes. Someone who adds you from your invite sends `{t: "hello", k}`; a matching token makes them a contact instead of a request, for the first 25 people per token (`me.inviteTok` is replaced when you make a new link).
- `j` is your relay's join code when it is invite-only, so the person you invite can sign up there.
- Inside the Android app, `<app>` is the web copy of the app your relay serves (the relay URL without its last path segment).

## Envelope (what the relay stores)

```
ephPub (65) | iv (12) | AES-GCM(K_outer, pad(JSON inner), AD = ephPub)
K_outer = HKDF(ECDH(eph, recipientKey), salt = 0^32, info = "hush/v2/outer")
inner   = { v: 4, f: senderPub, b: senderBox, r: senderRelay, n: senderName,
            q?: senderCard, qa?: cardTimeOfRecipientHeld, s: sessionId, h: header, c: ratchetCiphertext }
```

- **recipientKey** is the recipient's newest prekey when the sender holds a fresh card for them, and otherwise their identity key. The recipient tries its prekeys (newest first), then its identity key. A stolen identity key alone therefore can't open recorded envelopes that were sealed to a prekey that has since been deleted.
- **pad** adds trailing spaces (valid JSON) up to 1, 4, 16 or 32 KiB plus a random tail of up to an eighth of that size class; larger payloads (a profile being moved) go up in 16 KiB steps.
- A fresh ephemeral key per message hides the sender from the relay. The relay sees only the recipient's box, the time and the size class.

## Sessions and the Double Ratchet

The Double Ratchet follows Signal's specification, without header encryption (the outer layer already hides headers from the relay). `sessionId` is 16 random bytes chosen by whoever starts the session.

**Opening (v4, X3DH-style, no one-time prekeys).** Alice knows Bob's card:

```
SK = HKDF(DH(IKa, SPKb) ‖ DH(EKa, IKb) ‖ DH(EKa, SPKb), salt = sessionId, info = "lullwire/v4/x3dh")
Alice: DHs = new key, DHr = SPKb, (RK, CKs) = KDF_RK(SK, DH(DHs, SPKb))
Bob:   DHs = SPKb, DHr = none, RK = SK; the first message then performs a DH ratchet step
```

Until Bob answers, Alice's headers also carry `e = EKa` and `sp = SPKb`, so Bob can build the session from any of her opening messages, whichever arrives first. Only the two identity holders can derive `SK`, which authenticates both sides. After Bob deletes `SPKb`, a stolen identity key can't read recorded opening messages.

**Opening (v2, legacy).** For a contact whose card is unknown or too old: `RK = HKDF(ECDH(IKa, IKb), salt = sessionId, info = "hush/v2/root")`, Alice's `DHr` is Bob's identity key, and Bob uses his identity key as his first `DHs`. Hush Relay 0.5 apps only speak this.

**Chains.** `KDF_RK(rk, dh) = HKDF(dh, salt = rk, info = "hush/v2/rk")` → 64 bytes (new root key and chain key). `KDF_CK: next = HMAC(CK, 0x02), mk = HMAC(CK, 0x01)`.

**Message encryption.** AES-GCM with `mk`, a random 12-byte IV, and

```
AD = senderPub "|" recipientPub ‖ "|" JSON([b, r, n, q ? [q.s, q.t, q.g] : null, qa ?? null]) ‖ JSON(header)     (v4)
AD = senderPub "|" recipientPub ‖ JSON(header)                                                           (v2)
header = {dh, pn, n} or, on opening messages, {dh, pn, n, e, sp}
```

In v4 every field of the inner envelope is authenticated by the ratchet, so even someone who could open the outer layer can't change the sender's mailbox, relay, name or card. An app sends `v: 4` to contacts whose card it holds and `v: 2` otherwise (with its own card attached, which 0.5 apps ignore and 0.6 apps verify by its signature).

**Other rules.**
- Out-of-order messages: up to 200 skipped keys per step, 500 stored in total.
- Decryption runs on a copy of the state, which is saved only if it succeeds.
- `sessionId` must be 22 base64url characters (16 bytes). Sessions are keyed by `sessionId`. Receiving on a session makes it the active one, and the 4 most recent are kept, so two people starting at the same time converge. A session id is only ever opened once (the last 300 are remembered), and opening messages older than the moment this copy of the profile was created are refused, so a relay can't replay old sessions.

Message bodies are JSON with an authenticated timestamp: `{t: "msg", id, txt, ts}`, `{t: "reset", id, ts, why?}`, `{t: "hello", k, ts}` or a call message (below). A reset is sent after a profile moves to a new device (ratchet state never travels) and, with `why: "upgrade"`, once after updating from Hush Relay 0.5 (whose ratchet keys can't be exported into the new encrypted storage).

## Relay API (all POST, at `/relay.php`; the Go relay also answers at `/relay`)

| Action | Request | Result |
|---|---|---|
| `?a=send` | the recipient's box (32 lower-case hex characters), then the raw envelope bytes (93 bytes to 512 KiB) | `{ok}`; at most 500 pending per box. The box travels in the body so it never appears in a request line or access log |
| `?a=put&box=<32hex>` | raw envelope bytes | LEGACY (apps before 0.6.1): like `send`, with the box in the URL. Clients that get `400 bad action` or `bad s` for `send` from an older relay fall back to it |
| `?a=get&wait=<0..20>` | `{"s": secret}` | `[{id, d: base64}]`, waiting up to `wait` seconds for mail |
| `?a=ack` | `{"s": secret, "ids": [...]}` | deletes delivered mail |
| `?a=rput` | `{"l": 32hex, "t": 64hex, "d": b64url}` | stores a recovery slot; an existing slot needs the same `t` |
| `?a=rget` | `{"l"}` | `{d}` or 404 |
| `?a=rdel` | `{"l", "t"}` | deletes a slot |
| `?a=info` | `{}` | `{v: 2, invite: bool, calls: bool, mail: bool}` (Go relay; the PHP relay answers 400, which the app reads as "open, no calls, no live connection") |
| `?a=join` | `{"s": secret, "code"}` | registers `box(s)` as a member of an invite-only relay; 403 for a wrong code |

**Invite-only relays** (Go relay with `-join-code`) keep a list of member mailboxes. `put` to a non-member box answers 404 `unknown box`, so strangers can't use the relay as a free mailbox; `rput` needs the `s` of a member. `get` and `ack` for a non-member answer like an empty mailbox. The relay keeps `SHA-256("lullwire-join|" + code)` in memory, never the code. Wrong codes are limited to 10 per client per hour and 60 per minute overall; the right code is always accepted.

**Private path** (Go relay with `-path /<secret>/`): everything above, the app and `/live` move under that prefix, and `/` shows a plain placeholder page. It keeps scanners and casual visitors from recognising the server; it is not access control (the join code is).

Undelivered mail expires after 14 days. The relay keeps `sha256(t)`, never `t`.

## Live connection (Go relay)

The app keeps two WebSockets open at `/live` (the relay URL with its last path segment replaced, `https` → `wss`). To a network observer they are long-lived HTTPS connections to your server.

**Mail connection** (receiving). The first text frame, within 10 seconds, is `{"op":"mail","s":secret,"cover":bool}`; the relay answers `{"op":"ready","mail":true}` (on an invite-only relay, only for member mailboxes). Then:

| Direction | Frame | Meaning |
|---|---|---|
| relay → app | text `{"op":"m","id","d"}` | a pending or newly arrived envelope (base64) |
| app → relay | text `{"op":"ack","ids":[...]}` | delete delivered mail |
| relay → app | text `{"op":"n","id","d"}` | cover traffic (when `cover` was true): random bytes the size of a 1 KiB-class envelope; the app answers with an ack for a random id |

An envelope is pushed once per connection; anything unacknowledged is pushed again on the next one (the app reconnects after a storage error for that reason). At most about 2 MiB is in flight unacknowledged.

**Send connection** (delivering). It carries nothing that identifies the app's mailbox: the first frame is `{"op":"send"}` (on an invite-only relay `{"op":"send","j": SHA-256("lullwire-join|" + joinCode)}`, which only shows that the app was invited), answered with `{"op":"ready","send":true}`. The app opens and closes it on its own random schedule, not with the mail connection; until it is up, deliveries go over HTTPS. Deliveries therefore aren't tied to the sender's mailbox, just as with plain HTTPS deliveries; a relay that sees IP addresses can still guess (known limit 3).

| Direction | Frame | Meaning |
|---|---|---|
| app → relay | binary `0x01 ‖ requestId (4, BE) ‖ box (16) ‖ envelope` | deliver to a mailbox on this relay |
| app → relay | binary `0x00 ‖ requestId (4) ‖ 16 random bytes ‖ random bytes` | cover traffic, sized like a 1 KiB-class delivery |
| relay → app | text `{"op":"put","r":requestId,"ok":true}` or `{…,"e":status}` | result, with HTTP-like status codes (404, 413, 429, 503, 507); cover traffic gets `ok` too |

Deliveries pass exactly the checks an HTTP `put` does, including the relay-wide cap on concurrent heavy work. Deliveries to contacts on other relays go over HTTPS.

**Limits.** Each kind of connection counts like a long-poll towards the per-client limit (6 each, or 2 mail connections per mailbox behind Tor), and new connections are limited to 60 per client per minute. Behind Tor, where clients look alike, there is also a relay-wide budget (1,200 per minute), charged only for connections that passed every other check (membership for mail, the join proof for sending), so on an invite-only relay strangers can't use it up. The relay remembers a mailbox for quicker answers only once mail has arrived for it. It pings at varying intervals (20 s ± 25%); 60 seconds without data or an answered ping ends a connection.

**Cover traffic.** With it on, both directions carry noise shaped like the real traffic, with the same sizes, replies and acknowledgements, at random intervals of 20–90 seconds (about 1 MB an hour), so someone watching the network can't tell real sends and deliveries from noise. Without the live connections (PHP relay, or a proxy that doesn't pass WebSockets), the app long-polls with randomised waits (14–20 s) and gaps.

## Calls

Calls are one-to-one, audio or video, and travel through the caller's relay over a WebSocket at `/live`. The relay forwards opaque binary frames between the two people in a room and can't decrypt them. There is no peer-to-peer connection, so neither side learns the other's IP address.

**Setting up.** The caller picks `room` (32 random bytes, hex), `key` (32 random bytes) and a call id, opens the room, and only then sends through the ratchet: `{t: "call", id, room, key, live, video, ts}`. The callee joins only if the caller is an accepted contact, `live` is exactly the caller's relay's call address, `room` is 64 hex characters and the message is under a minute old. Either side can send `{t: "call-decline", id, busy?}` or `{t: "call-end", id}`.

**Room protocol.** The first text frame, within 10 seconds, is `{"op":"open","room","s"}` (caller; `s` must be a member's secret on an invite-only relay) or `{"op":"join","room"}`. The relay answers `{"op":"ready","peer":bool}` and later `{"op":"peer","here":bool}`; after that only binary frames are forwarded. Limits: 2 people per room, 500 rooms, 4 rooms per client, 256 KiB per frame, about 600 KB/s per connection (2 MB burst), rooms close after 4 hours or 2 minutes alone, 60 seconds of silence ends a connection.

**Media frames.**

```
k_dir  = HKDF(key, salt = 0^32, info = "hush/call/v1/" + ("caller" | "callee"))    one key per direction
frame  = type (1) | seq (8, big-endian) | AES-GCM(k_dir, iv = 0^4 | seq, AD = type | seq, ts (8, float64) | flags (1) | payload)
type   = 1 audio (Opus, 48 kHz mono, 32 kbit/s, 20 ms) · 2 video (VP8, 640×360, 15 fps, 600 kbit/s) · 3 control (JSON)
```

`seq` counts up from 0 per direction and must strictly increase; a repeated or older `seq` is dropped, so frames can't be replayed. Video frames set `flags & 1` on keyframes. Control messages are `{k: "kf"}` (ask for a keyframe), `{k: "av", a, v}` (microphone and camera on or off) and `{k: "bye"}`. A new call uses a new key, so nothing links one call's traffic to another's.

## Recovery words

- **The words:** 8 random words from the BIP39 English list (88 bits). Sets of 6 words (66 bits) made by Hush Relay 0.5 still work; Settings offers to replace them, and the old slot is deleted once the new words are confirmed.
- **Key derivation:** `PBKDF2(words, salt, 600 000 iterations)` produces 80 bytes, split into the locator `l` (16 bytes, hex), the write token `t` (32 bytes, hex) and the key `k` (32 bytes). The salt is `"lullwire/recovery/v2"` for 8 words and `"hush/recovery/v1"` for 6.
- **The slot:** `AES-GCM(k, JSON account padded to a multiple of 16 KiB, AD = "lullwire/recovery:" + l)` (6-word slots: `AD = "hush-recovery:" + l`), re-uploaded whenever the contact list changes.
- The salt is the same for everyone, so a relay holding many slots can test a guess against all of them at once; with 88 bits and 600 000 PBKDF2 rounds per guess that is still far out of reach.
- **The account bundle:** `{v: 3, me: {jwk, pub, secret, box, name, relay, rec, join?, inviteTok}, contacts: [{pub, box, relay, name, verified, blocked}]}`. When importing, the device checks that the private key matches `pub` and the mailbox matches its secret, and makes a fresh prekey.

## Moving to a new device

1. The new device creates an ephemeral key pair `E` and a temporary mailbox `(s, b = box(s))`. It shows `https://<app>/#link=` followed by `base64url({r, e: E.pub, s})` as a QR code. It also shows the 12-digit code `SHA-256(E.pub)[0..16 hex] mod 10^12`.
2. The old device scans the QR (move codes are accepted only from Scan, never from links or pasted text), shows the same code, and waits for the user to approve. On an invite-only relay it uses its join code (only with its own relay) to admit the temporary mailboxes.
3. The old device seals `{t: "link", data: accountBundle, ack: {r, b: ackBox, n: nonce}}` (`nonce` = 32 random bytes, hex) to `E.pub` with the envelope's outer layer, delivers it, and waits up to 2 minutes for a message in `ackBox` that starts with `nonce`.
4. The new device opens the bundle, asks the user to confirm which profile it is receiving, imports it, sends the acknowledgement (`nonce` followed by 64 random bytes; the relay never sees `nonce` in the clear, so it can't fake this), and sends `reset` to every contact.
5. The old device erases itself only after the acknowledgement arrives.

## Encrypted backup file

`LULLWIRE1.` + `b64url(salt)` + `.` + `b64url(AES-GCM(PBKDF2(passphrase, salt, 600 000), bundle, AD = "lullwire/backup"))`, saved as `.lullwire`. Files from Hush Relay 0.5 (`HUSH3.` / `HUSH2.`, `AD = "hush-backup"`, `.hush`) still restore.

## Storage on the device (the vault)

Everything the app stores is in IndexedDB database `lullwire`, encrypted:

- A random 32-byte master secret `MK` gives `K_enc = HKDF(MK, info = "lullwire/vault/v1/enc")` (AES-256-GCM) and `K_blind = HKDF(MK, info = "lullwire/vault/v1/blind")` (HMAC-SHA-256).
- Each record is `AES-GCM(K_enc, JSON, AD = "lullwire/vault|" + store + "|" + key)`, so records can't be swapped between places. The identity key, the profile, prekeys, contacts (with their ratchet state) and every message are records.
- Contacts and messages are indexed by `HMAC(K_blind, contactId)[0..32 hex]`, so the database reveals neither contact ids nor which messages belong to whom.
- The only clear record is the vault header, saying how `MK` is protected: by the Android Keystore (`mode: "android"`, an AES-GCM key in the phone's keystore that can't be exported), by an app-lock passphrase (`mode: "pass"`, `AES-GCM(PBKDF2(passphrase, salt, 600 000), MK, AD = "lullwire/vault/pass")`), or stored as-is in a plain browser (`mode: "plain"`, where the browser has no safer place for it).
- Turning on the app lock makes a new `MK` and re-encrypts every record with it, in one transaction with the new header.
- On first start after updating from Hush Relay 0.5, the plaintext database `hush2` is moved into the vault. A `migrating` flag (set before anything else) makes an interrupted move start over on the next launch; `hush2` is deleted only after a complete move.

## Signed releases (web app)

`web/release.json = {m: manifest JSON, s: ECDSA-P256-SHA256(releaseKey, m)}`, where the manifest is `{v: 1, version, key, files: {path: sha256hex}}` and lists every app file except `sw.js`. The release key's public half is pinned in `sw.js`. With a key pinned, the service worker serves the app only from a cache whose every file matched a signed manifest, and switches to a new release only if it is signed by the pinned key, complete, and has a higher version; it reports anything else to the page. It fetches `release.json` once per check and uses only the bytes it verified. Every page load inside the app's scope gets the verified `index.html`, and app files are never fetched from the network once installed (a missing one is an error, not a fallback). See [RELEASING.md](RELEASING.md).

## Legacy and removal plan

Code paths marked `LEGACY` in the source exist only to talk to, or import from, Hush Relay 0.5: v2 session openings and envelopes, 6-word recovery, `HUSH2`/`HUSH3` backups, the `hush2` database migration, `HUSH_*` settings and `HUSH_CONFIG`. They are planned for removal in 0.8, once 0.5 apps are no longer in use; `tests/compat.test.js` checks them against a frozen copy of the 0.5 crypto core until then.
