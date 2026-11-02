# Lullwire Relay protocol (v3)

All cryptography uses the browser's WebCrypto API: ECDH P-256, HKDF-SHA-256, HMAC-SHA-256, AES-256-GCM and PBKDF2-SHA-256. Encodings are base64url without padding unless noted.

## Identity and mailbox

- **Identity key:** an ECDH P-256 key pair generated on the device. The public key (65-byte raw, base64url) is the identity.
- **Mailbox:** `secret` = 32 random bytes as hex, and `box` = first 32 hex characters of `SHA-256(secret)`. Anyone may deliver to `box`; reading and deleting require `secret`, which is only ever sent in a POST body.
- **Contact id:** the first 32 hex characters of `SHA-256(rawPub)`. A different key is a different contact.
- **Safety number:** `SHA-256(pubA ‖ pubB)` with the two keys sorted. The first 40 hex characters are shown in groups of 5.
- **Invite:** `https://<app>/#i=` followed by `base64url(JSON {p: pub, b: box, r: relayURL, n: name, k: inviteToken, j?: joinCode})`. It travels in the URL fragment, so it never reaches a server. `k` is 12 random bytes: someone who adds you from your invite sends `{t: "hello", k}`, and a matching token lets your app accept them as a contact instead of a request, for the first 25 people per token (`me.inviteTok` is replaced when you make a new link). `j` is your relay's join code when it is invite-only, so the person you invite can sign up there. Inside the Android app, `<app>` is the web copy of the app your relay serves (the relay URL without its last path segment).

## Envelope (what the relay stores)

```
ephPub (65) | iv (12) | AES-GCM(K_outer, pad(JSON inner), AD = ephPub)
K_outer = HKDF(ECDH(eph, recipientIdentity), salt = 0^32, info = "hush/v2/outer")
inner   = { v: 2, f: senderPub, b: senderBox, r: senderRelay, n: senderName,
            s: sessionId, h: {dh, pn, n}, c: ratchetCiphertext }
```

`pad` adds trailing spaces up to 1, 4, 16 or 32 KiB. A fresh ephemeral key per message hides the sender from the relay. The relay sees only the recipient's box, the time and the size bucket.

## Double Ratchet

The construction follows Signal's Double Ratchet specification, without header encryption (the outer layer already hides headers from the relay).

- **Session root:** `HKDF(ECDH(idSelf, idPeer), salt = sessionId, info = "hush/v2/root")`. `sessionId` is 16 random bytes chosen by whoever starts the session. Only the two identity holders can derive the root, which is what authenticates the sender.
- **Initiator:** generates a ratchet key `DHs`, sets `DHr` to the peer's identity key, then runs `RK, CKs = KDF_RK(root, ECDH(DHs, peerId))`.
- **Responder:** uses its identity key as its first `DHs` and creates the session when the first message for an unknown `sessionId` arrives.
- **KDF_RK:** `HKDF(dhOut, salt = RK, info = "hush/v2/rk")` produces 64 bytes, giving the new `RK` and a chain key.
- **KDF_CK:** `next = HMAC(CK, 0x02)` and `mk = HMAC(CK, 0x01)`.
- **Message encryption:** AES-GCM with `mk`, a random 12-byte IV, and `AD = senderPub "|" recipientPub ‖ JSON(header)`.
- **Out-of-order messages:** up to 200 skipped keys per step, 500 stored in total.
- **Failure handling:** decryption runs on a copy of the state, and the state is saved only if it succeeds.
- **Several sessions per contact:** sessions are keyed by `sessionId`. Receiving on a session makes it the active one, and the 4 most recent are kept, so two people starting at the same time converge.

Message bodies are JSON: `{t: "msg", id, txt, ts}`, `{t: "reset", id, ts}`, `{t: "hello", k, ts}` or a call message (below). A reset is sent after an account moves to a new device, because ratchet state never travels.

## Relay API (all POST, at `/relay.php`; the Go relay also answers at `/relay`)

| Action | Request | Result |
|---|---|---|
| `?a=put&box=<32hex>` | raw envelope bytes (93 bytes to 512 KiB) | `{ok}`; at most 500 pending per box |
| `?a=get&wait=<0..20>` | `{"s": secret}` | `[{id, d: base64}]`, waiting up to `wait` seconds for mail |
| `?a=ack` | `{"s": secret, "ids": [...]}` | deletes delivered mail |
| `?a=rput` | `{"l": 32hex, "t": 64hex, "d": b64url}` | stores a recovery slot; an existing slot needs the same `t` |
| `?a=rget` | `{"l"}` | `{d}` or 404 |
| `?a=rdel` | `{"l", "t"}` | deletes a slot |
| `?a=info` | `{}` | `{v: 2, invite: bool, calls: bool}` (Go relay; the PHP relay answers 400, which the app reads as "open, no calls") |
| `?a=join` | `{"s": secret, "code"}` | registers `box(s)` as a member of an invite-only relay; 403 for a wrong code |

**Invite-only relays** (Go relay with `-join-code`) keep a list of member mailboxes. `put` to a non-member box answers 404 `unknown box`, so strangers can't use the relay as a free mailbox; `rput` needs the `s` of a member. `get` and `ack` for a non-member answer like an empty mailbox. The relay stores `SHA-256("lullwire-join|" + code)`, never the code. `join` is limited to 10 tries per client per hour and 60 per minute overall.

**Private path** (Go relay with `-path /<secret>/`): everything above, the app and `/live` move under that prefix, and `/` shows a plain placeholder page. It keeps scanners and casual visitors from recognising the server; it is not access control (the join code is).

Undelivered mail expires after 14 days. The relay keeps `sha256(t)`, never `t`.

## Calls

Calls are one-to-one, audio or video, and travel through the caller's relay over a WebSocket at `/live` (the relay URL with its last path segment replaced, `https` → `wss`). To a network observer this is an ordinary long-lived HTTPS connection to your server. The relay forwards opaque binary frames between the two people in a room and can't decrypt them. There is no peer-to-peer connection, so neither side learns the other's IP address.

**Setting up.** The caller picks `room` (32 random bytes, hex), `key` (32 random bytes) and a call id, opens the room, and only then sends through the ratchet: `{t: "call", id, room, key, live, video, ts}`. The callee joins only if `live` is on the same host as the caller's relay, `room` is 64 hex characters and the message is under a minute old. Either side can send `{t: "call-decline", id, busy?}` or `{t: "call-end", id}`.

**Room protocol.** The first text frame, within 10 seconds, is `{"op":"open","room","s"}` (caller; `s` must be a member's secret on an invite-only relay) or `{"op":"join","room"}`. The relay answers `{"op":"ready","peer":bool}` and later `{"op":"peer","here":bool}`; after that only binary frames are forwarded. Limits: 2 people per room, 500 rooms, 4 rooms per client, 256 KiB per frame, about 600 KB/s per connection (2 MB burst), rooms close after 4 hours or 2 minutes alone, 60 seconds of silence ends a connection.

**Media frames.**

```
k_dir  = HKDF(key, salt = 0^32, info = "hush/call/v1/" + ("caller" | "callee"))    one key per direction
frame  = type (1) | seq (8, big-endian) | AES-GCM(k_dir, iv = 0^4 | seq, AD = type | seq, ts (8, float64) | flags (1) | payload)
type   = 1 audio (Opus, 48 kHz mono, 32 kbit/s, 20 ms) · 2 video (VP8, 640×360, 15 fps, 600 kbit/s) · 3 control (JSON)
```

`seq` counts up from 0 per direction and must strictly increase; a repeated or older `seq` is dropped, so frames can't be replayed. Video frames set `flags & 1` on keyframes. Control messages are `{k: "kf"}` (ask for a keyframe), `{k: "av", a, v}` (microphone and camera on or off) and `{k: "bye"}`. A new call uses a new key, so nothing links one call's traffic to another's.

## Recovery words

- **The words:** 6 random words from the BIP39 English list, which is 66 bits.
- **Key derivation:** `PBKDF2(words, salt = "hush/recovery/v1", 600 000 iterations)` produces 80 bytes, split into the locator `l` (16 bytes, hex), the write token `t` (32 bytes, hex) and the key `k` (32 bytes).
- **The slot:** it holds `AES-GCM(k, JSON account, AD = "hush-recovery:" + l)`, re-uploaded whenever the contact list changes.
- **The account bundle:** `{v: 3, me: {jwk, pub, secret, box, name, relay, rec, join?, inviteTok}, contacts: [{pub, box, relay, name, verified, blocked}]}`. When importing, the device checks that the private key actually matches `pub`.

## Moving to a new device

1. The new device creates an ephemeral key pair `E` and a temporary mailbox `(s, b = box(s))`. It shows `https://<app>/#link=` followed by `base64url({r, e: E.pub, s})` as a QR code (`b` is derived from `s`). On an invite-only relay the old device uses its join code to admit the temporary mailboxes before delivering. It also shows the 12-digit code `SHA-256(E.pub)[0..16 hex] mod 10^12`.
2. The old device scans the QR, shows the same code, and waits for the user to approve.
3. The old device seals `{t: "link", data: accountBundle, ack: {r, b: ackBox, n: nonce}}` (`nonce` = 32 random bytes, hex) to `E.pub` with the envelope's outer layer, delivers it, and waits up to 2 minutes for a message in `ackBox` that starts with `nonce`.
4. The new device opens the bundle, imports it, sends the acknowledgement (`nonce` followed by 64 random bytes; the relay never sees `nonce` in the clear, so it can't fake this), and sends `reset` to every contact.
5. The old device erases itself only after the acknowledgement arrives.

## Encrypted backup file

`HUSH3.` + `b64url(salt)` + `.` + `b64url(AES-GCM(PBKDF2(passphrase, salt, 600 000), bundle, AD = "hush-backup"))`
