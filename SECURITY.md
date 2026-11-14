# Security

## Status

Lullwire Relay (named Hush Relay until 0.5) is **experimental and has not been audited by an independent security firm.** Each release has had internal adversarial review with working exploit scripts, and every confirmed finding was fixed with a regression test before release (see the audit log below). That is not a substitute for review by outside cryptographers.

Use it for everyday privacy, learning and experiments. If a bug could put you or the people you talk to at risk (activists, journalists, sources, people facing a hostile government), use [Signal](https://signal.org) or [SimpleX](https://simplex.chat).

## Reporting a vulnerability

Please report privately through GitHub's **Report a vulnerability** button (the Security tab of this repository). Don't open a public issue. Include steps to reproduce if you can. Fixed issues are listed in the audit log below, with credit if you want it.

## What it is designed to protect

| Threat | Protection |
|---|---|
| Relay operator reading messages | End-to-end encryption (signed-prekey session opening, Double Ratchet, AES-256-GCM) |
| Relay operator learning who sent a message | Sealed sender: a fresh ephemeral key per envelope |
| Relay operator or network learning exact message length | Padding to size classes with a random tail; large payloads in 16 KiB steps |
| Someone who later steals a device reading past captured traffic | Forward secrecy for message bodies, including a session's first messages once the signed prekey is deleted (see limit 1) |
| Forged or tampered messages | Authenticated encryption bound to both identities, the header, and (v4) the sender's mailbox, relay, name and card |
| Replayed messages or replayed old sessions | Ratchet counters, single-use session ids, authenticated timestamps |
| Someone swapping the mailbox in an invite, or quietly re-routing a contact | Address cards signed by the identity key; unsigned changes always ask first |
| Someone who copies the device's files | Everything stored encrypted (the vault); key in the Android Keystore, or behind an app-lock passphrase |
| Code that leaks keys through an export call | Identity keys held as non-extractable WebCrypto keys at runtime |
| A server changing the app's code | Installed web apps run only releases signed with the pinned release key (see limit 4); the APK is signed |
| A network observer timing your messages | One long-lived connection for everything; optional cover traffic both ways |
| Relay operator opening or replacing the recovery backup | 88-bit random words, PBKDF2 600k, token-guarded slot |
| Unsolicited senders posing as your contacts | Unknown senders arrive as *requests*, marked unverified; safety numbers |
| Relay operator or network listening to calls | Per-call random key sent inside the ratchet; one AES-GCM key per direction; frames bound to type and sequence number |
| Replayed or reordered call frames | Strictly increasing per-direction sequence numbers, checked inside the authenticated data |
| A contact or relay steering your app into a call elsewhere | Calls are joined only from accepted contacts, at exactly their relay's call address |
| Strangers using your relay as free storage | Invite-only mode (join code); only member mailboxes can receive mail or store recovery slots |
| Scanners recognising the server as a messenger | Private path with a plain front page; calls and messages are ordinary HTTPS to your server |
| Other Android apps reading your keys | App-private storage, Keystore-wrapped vault, no cloud backup or device transfer, screenshots blocked in release builds |
| Abuse of a public relay | Per-client rate limits (real client address, also behind a proxy or tunnel), per-mailbox quotas, disk floor, expiry; the live connection shares every limit |

## Known limits (by design, for now)

1. **No one-time prekeys.** A session's first messages get forward secrecy once the signed prekey they used is deleted (prekeys are replaced every 14 days and kept 45). Until then, someone who records traffic and later steals the device can read those first messages. Sessions with contacts still on Hush Relay 0.5, or whose prekey we hold is too old, open the older way, which depends on identity keys alone. Ongoing conversations always have forward secrecy.
2. **Key-compromise impersonation.** Someone who steals your identity key can pose as anyone *to you*.
3. **The relay sees metadata:** IP addresses, timing, which mailbox receives mail, the size class, and whether mail is waiting. Deliveries don't name the sender, and the sending connection opens and closes on its own random schedule, but a relay that sees your IP address can usually still match it to your receiving connection. Tor hides your address, not the timing of what you send. Cover traffic hides timing from the network, not from the relay, and doesn't hide that you use Lullwire or are online. Use a relay you trust, Tor, or a tunnel that hides client IPs if this matters.
4. **Web delivery.** On a first visit, the browser trusts whatever code the server sends. After that, an installed web app runs only releases signed with the pinned key, but browsers always let a server replace the service worker (`sw.js`) itself, so a fully compromised server can still ship new code. The Android app, or a pinned IPFS CID, avoids this. Whoever holds the release signing key can sign anything; it is kept offline.
5. **Shared origins.** Browser storage is per origin. Don't host the app on an origin that also runs other people's code (for example, a shared cPanel domain with other apps).
6. **Device linking** uses a 12-digit comparison code (about 40 bits) inside a 10-minute window. Compare the code; never approve a request you didn't start.
7. **Invites from Hush Relay 0.5 are not signed.** Someone who intercepts one can swap the mailbox in it (not the key). Invites made by Lullwire carry a signed card. Verify safety numbers once either way.
8. **Calls go through the caller's relay.** It can see that a call happened, when, for how long and roughly how much data it used. It can't see or hear the call. It does learn the caller's mailbox (the caller proves membership when opening the room), and when the callee uses the same relay it can usually link the two by timing. There is no peer-to-peer mode, so neither side learns the other's IP address.
9. **The private path is not a secret from the relay host or your network provider's view of your server.** HTTPS hides the path and content, but not the server's address or name. The join code, not the path, is what keeps strangers out.
10. **Android app updates are your responsibility.** There's no store to update it: check the APK's SHA-256 and signing-certificate fingerprint against the release page, and keep Android System WebView updated, since the app runs on it. Lullwire's package (`dev.altru.lullwire`) is new: it installs next to Hush Relay, and you move your profile across with **From my other device**.
11. **One device per account.** Recovering or linking while another copy is still active leads to lost messages. Erase the old copy.
12. **Some sizes are only roughly hidden.** Messages are padded to size classes; recovery slots and moved profiles go up in 16 KiB steps, which still hints at the size of your contact list.
13. **6-word recovery sets are weaker.** Words made before 0.6 carry 66 bits and share one salt, so a relay holding many slots can test a guess against all of them at once. New sets have 8 words (88 bits); Settings offers to replace old ones.
14. **Messages with Hush Relay 0.5 contacts** use the v2 format, where the sender's mailbox, relay and name are protected by the outer layer only, not bound into the ratchet. v4 binds them.
15. **Invite links can be forwarded.** Anyone holding your link can add you as a contact: the first 25 people directly, later ones as requests. Make a new link from the invite screen if one spreads too far. Whether a link lets someone *join* an invite-only relay depends on the relay's owner: an owner's invite admits one person, once, within 7 days; the shared join code (in older invites and in every member's settings) admits anyone who has it until the owner switches it off.
16. **One key, two uses.** The identity key does both ECDH and ECDSA (signing prekeys and cards), as Signal's XEdDSA does with its identity key. This relies on the joint security of the two schemes on one key, which is studied and believed sound but is an assumption.
17. **Storage in a plain browser.** Without an app lock, a browser keeps the vault key next to the data (browsers have no safer place), so someone who copies the browser profile can read it. Turn on the app lock, or use the Android app. An app-lock passphrase can be guessed offline from copied files (PBKDF2, 600 000 rounds per guess), so choose a long one.
18. **Background mode on Android** keeps the app running while closed and shows a "connected" notification. With an app lock on, nothing is received after a restart until you unlock. Message notifications show no names or text unless you turn names on.
19. **No independent cryptographic review yet.**
20. **The relay owner sees how the relay is used**, as any relay host could: how many members, when each joined and was last active, how much mail waits for each, daily counts, live connections. Members appear under anonymous ids; the owner's app names those that are its own contacts, on the device. The owner can remove members and restart the relay, not read anything. Owner access is a token held by one device (not in backups or moves) and claimed with a one-time code from the server, so anyone who controls the server can take it over; that person could read the data folder anyway.
21. **Notifications while the browser app is closed use a push service.** With it turned on, the relay sends Apple's, Google's, Mozilla's or Microsoft's push service an encrypted, empty signal whenever mail arrives and the app isn't connected. That service learns when the device gets messages and the relay's address, never who from or what; the popup only says "New message". It's off unless each person turns it on, the relay can switch it off (`-push=false`), and it's off by default on onion relays. Popups while the app is open but in the background need no servers; with names on, they show the sender and the start of the message on the lock screen.

## Deployment checklist

- Serve over HTTPS. Browsers refuse the crypto APIs otherwise.
- Start with `lullwire-relay init`: it sets up the private path, join code and the right proxy or Tor settings, and prints a hardened systemd unit.
- Keep `LULLWIRE_DATA` outside the web root unless you're on Apache with `.htaccess` enabled (`AllowOverride`); the relay can't detect an Apache that ignores `.htaccess`. Elsewhere, the relay refuses to start when the data folder is inside the web root.
- Behind a proxy on another machine, list it in `LULLWIRE_TRUSTED_PROXIES` so limits apply per real client. Local proxies and tunnels are trusted automatically.
- Make sure the proxy passes WebSocket upgrades to `…/live`: calls and the live mail connection use it (Caddy and Cloudflare Tunnel do by default; nginx needs `proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";`). Without it, the app falls back to long-polling and calls don't work.
- Keep anti-framing headers on: `web/.htaccess` (Apache) and `scripts/router.php` (`php -S`) send them. On Caddy or nginx, add `Content-Security-Policy: frame-ancestors 'none'`.
- Turn off access logs you don't need.
- Behind a Tor onion service, run the Go relay with `-onion`; otherwise every visitor shares one client identity for rate limits. Back up the onion service's key folder and keep it private.
- Use the private setup: `-path` and `-join-code`. Share the app only through invites.
- Claim the owner dashboard (`lullwire-relay -owner-code`), then switch the shared join code off, so people join only through your single-use invites and removing someone keeps them out.
- Maintainers: keep the web release signing key (`~/.lullwire-relay/web-signing.pem`) and the Android signing key (`~/.lullwire-relay/release.jks`) offline and backed up; publish the APK's SHA-256 and certificate fingerprint and the release key fingerprint with each release ([RELEASING.md](docs/RELEASING.md)).
- Keep the host patched. For a phone relay, use a device that still gets security updates.

## Audit log

### 2026-10-31: internal adversarial review (pre-release)

A separate reviewer was given only the code and a threat model. It wrote proof-of-concept exploits for the issues it found. Every confirmed issue below was fixed and has a regression test in `tests/`.

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | High | Data folder could be served by URL on nginx, Caddy or `php -S` | `LULLWIRE_DATA` / `relay.config.php`; refuses to run when exposed; hardened router |
| 2 | Medium-high | A malicious relay could replay an old session opening and break or re-route a conversation | Single-use session ids, authenticated timestamps, replay floor after restore, newest session wins |
| 3 | Medium | An oversized relay URL or contact spam could silently stop recovery-backup updates | Strict relay URL validation; unknown senders become requests excluded from backups; sync errors shown |
| 4 | Medium | Unauthenticated writes could fill the disk | Rate limits, per-mailbox quotas, free-disk floor, expiry of stale slots and temp files |
| 5 | Low | `http://localhost:@evil.com` passed relay validation | URL parsing with exact protocol/host checks |
| 6 | Low | Array query parameters caused a 500 error | Type checks on every parameter |
| 7 | Medium | Scanning a crafted invite silently re-routed an existing contact | Confirmation before any change to a known contact |
| 8 | Medium | A web link could open the "move account" screen; pages could be framed | URL link requests ignored on existing accounts; frame-busting and `frame-ancestors` |
| 9 | Medium-low | 8-digit link code; the new device accepted any account | 12-digit code; the new device confirms which account it is receiving |
| 10 | Medium-low | Idle long-polls could tie up every relay worker | Concurrent long-polls capped per client; unused mailboxes answer quickly |
| 11 | Low | A stranger could use a contact's display name | Message requests, unverified tags, safety numbers |
| 12 | Low | Messages lost to a local storage error were deleted from the relay | Kept on the relay and retried |
| 13 | Low | Imported account bundles weren't consistency-checked | Mailbox, key and relay checks on import |

### 2026-10-31: second review (of the fixes)

The same reviewer re-tested every fix. The replay, cryptography, input, invite, link and import fixes held, and simultaneous session starts still converge. It found 7 further issues, now fixed with regression tests:

| # | Severity | Finding | Fix |
|---|---|---|---|
| 14 | High | Behind a tunnel or proxy, every user shared one rate-limit identity, so one attacker could block delivery for all; capped apps also polled in a tight loop | Real client address from local proxies (`CF-Connecting-IP`, `X-Forwarded-For`); `429` + `Retry-After`; client never polls faster than every 1.5 s |
| 15 | Medium | A contact's new device with a slow clock could leave the conversation stuck on the old session | Sessions chosen by arrival, not timestamps; a reset on a freshly opened session always takes over |
| 16 | Medium-low | After recovering with words, replay protection only reached back to the last backup sync | Replay floor set to the moment of recovery |
| 17 | Low | A far-future timestamp could freeze a contact's mailbox updates | Timestamps clamped to local time plus allowed skew |
| 18 | Low | A data folder elsewhere under the document root passed the exposure check | Also checked against the server's document root |
| 19 | Low | The largest allowed account didn't fit the relay's limits | Limits raised; a worst-case 500-contact account is tested |
| 20 | Low | Message requests could fill the contact limit and block real new contacts | Requests capped separately (200, oldest dropped); a Delete button for requests |

### 2026-11-01: Go relay review

A separate reviewer tested the new Go relay against the same threat model, with working exploits. Fixed, each with a regression test:

| # | Severity | Finding | Fix |
|---|---|---|---|
| 21 | High | In onion mode, visitor-supplied forwarded-address headers bypassed the per-mailbox limits | Onion mode ignores all visitor headers; one configurable header elsewhere |
| 22 | High | Recovery-slot misses slept while holding a lock shared with deliveries, stalling them | Lookups take no lock |
| 23 | High on small devices | Parallel fetches of a full mailbox could push memory past 2 GB | Streamed responses capped at about 2 MiB; at most 128 heavy requests at once |
| 24 | Medium | Shutdown cut off requests in flight | Waiting connections are answered, then the relay exits |
| 25 | Low | Smaller items: onion-wide budgets, bounded counters, a rare race in cleanup, stale cache tags with `-web`, timeouts, symlinked data folders, `CF-Connecting-IP` trusted without being chosen (also in the PHP relay) | Fixed |

### 2026-11-01: review of calls, private relays and the Android app

A separate review of the 0.5.0 additions (call rooms, invite-only mode and private path, call encryption, the Android app), with working proofs where possible. Fixed before release, each with a regression test where it can be tested automatically:

| # | Severity | Finding | Fix |
|---|---|---|---|
| 26 | High | In the Android app, a link from a web page, another app or a shared text could open the "move your profile" screen; one tap on Approve would have sent the profile to whoever made the link | Move codes are accepted only from Scan; links and shared text can't start a move |
| 27 | Medium | Invite links from outside the app added the contact without asking, revealing your identity to whoever made the link | Asks "Add NAME as a contact?" first |
| 28 | Medium | If a call ended while the camera or sound was still starting, the camera and microphone could stay on until the page reloaded | Checked after every wait during call setup; tracks are stopped |
| 29 | Medium | One client could hold every call room (a fresh mailbox per room behind Tor; a whole IPv6 /64 elsewhere) | IPv6 clients grouped by /64; joins counted per client; Tor relays warned to use a join code, which is required to open a room |
| 30 | Medium | A slow reader could make the relay buffer up to about 24 MB per connection | At most 1 MB queued per connection; media beyond that is dropped |
| 31 | Low | A muted call with the camera off was dropped after 60 seconds | Answered pings keep a connection alive |
| 32 | Low | A room could outlive its second person for up to 4 hours | The "alone" check repeats every 2 minutes |
| 33 | Low | Wrong join codes could lock out people who had the right one (shared limit behind Tor, global limit elsewhere) | Only wrong codes count towards the limits |
| 34 | Low | Message requests (strangers) could ring you, and a call address only had to match the host | Calls only from accepted contacts, at exactly their relay's call address |
| 35 | Low | The release keystore password was visible in the process list while signing | Passed through the environment |
| 36 | Info | Release builds allowed plain-http connections to localhost | Only debug builds do |
| 37 | Info | The built-in front page is identical on every relay | Startup note recommends `-cover` |
| 38 | Info | Fragmented or oversized control frames were accepted; text frames weren't counted against the bandwidth limit | Rejected; every frame counts |

Checked and found sound: WebSocket frame-length limits and masking, room isolation and 256-bit room ids, private-path normalisation (case, `//`, dot segments, encoded slashes), member file naming and constant-time code checks, per-direction call keys with no nonce reuse, the Android asset server, permission and intent handling.

### 2026-11-01: full audit of the whole repository (0.5.0)

A separate auditor reviewed the entire repository: the crypto core, both relays, the app, calls, the Android shell, scripts and docs. No critical or high-severity issues; the crypto core and the XSS surface held up. Fixed before release, with regression tests where they can be automated:

| # | Severity | Finding | Fix |
|---|---|---|---|
| 39 | Medium | The fix for #33 still checked the limits before the code, so enough wrong guesses blocked the right code too (relay-wide behind Tor) | The right code is always accepted; only wrong codes are checked against the limits |
| 40 | Medium | Anyone with the join code could register unlimited mailboxes, filling memory and disk on a small relay | New memberships limited per client and relay-wide, capped at 20,000, refused when the disk is nearly full; memberships not renewed for 180 days expire (the app renews its own on every start) |
| 41 | Medium | A forwarded invite link made every holder an accepted contact, so one person could fill the contact list (5,000 cap) and push real contacts out of the recovery backup | An invite link auto-accepts 25 people, then the rest arrive as requests; "Make a new link" on the invite screen; blocked contacts don't count towards the cap; any contact can be deleted; the backup keeps verified and recent contacts first (up to 900) and warns when some don't fit |
| 42 | Low | The PHP relay's "data folder exposed" check looked at the parent folder and didn't resolve symlinks | Resolves the data folder itself and refuses it inside the app folder or document root |
| 43 | Low | The device-move acknowledgement wasn't authenticated: a malicious relay could make the old device erase itself without the new one having the profile | The acknowledgement must carry a secret nonce that only travelled inside the sealed bundle |
| 44 | Low | Move codes were accepted from the "paste an invite" box | Refused there; moves start only from Scan |
| 45 | Low | Android's phone-to-phone transfer could copy the keys to a new phone | `dataExtractionRules` exclude everything from cloud backup and device transfer |
| 46 | Low | SECURITY.md said the relay can't tell which contact is calling | Corrected (known limit 8) |
| 47 | Info | During a move, your join code could be sent to a relay named in the scanned code; Go static checks were case-sensitive; envelope size documented wrongly; unpadded large payloads, a shared recovery salt and outer-layer-only sender fields were undocumented | Join code goes only to your own relay; checks compare in lower case; PROTOCOL corrected; known limits 12–15 added |

### 2026-11-02: review of 0.6 (Lullwire Relay)

A separate reviewer was given the 0.6 changes (protocol v4, the vault, the live connection, signed releases, the setup wizard, the Android background service) and the threat model, and wrote working proofs of concept. No critical issues; the ratchet, the X3DH-style opening, card signatures, vault record binding and the Android shell held up. Fixed before release, each with a regression test:

| # | Severity | Finding | Fix |
|---|---|---|---|
| 48 | High | Mail connections with made-up secrets grew the relay's memory without limit (also on invite-only relays), and made those mailboxes "known" again | Only existing mailboxes are remembered (capped); non-members can't open mail connections on invite-only relays; new live connections are rate limited |
| 49 | Medium | The service worker decided "newer" from one fetch of release.json and staged a second fetch, so an older signed release could be installed | One fetch, verified, then required to be newer |
| 50 | Medium | A new contact was added from an invite whose card didn't verify, or had been removed, without a warning | Invites with a bad card are refused; card-less (0.5) invites warn first |
| 51 | Medium | An interrupted move from the 0.5 database lost messages and left it on disk | A "migrating" flag set first; the move starts over until complete; hush2 deleted only after success |
| 52 | Medium | Deliveries over the mail connection told the relay which mailbox sent to which | A separate send connection that identifies nothing |
| 53 | Low–Medium | Cover traffic could be told apart from real traffic (no replies or acks, different sizes) | Noise has the same sizes, replies and acknowledgements as real traffic |
| 54 | Low | After a contact restored, they didn't get your card again for up to 14 days | A message without `qa` resets what the contact is known to hold |
| 55 | Low | Session ids of any length were stored (strangers could bloat storage) | Exactly 22 base64url characters |
| 56 | Low | After a local storage error the ratchet had already moved, so the retried message was lost (since #12); unacknowledged mail stalled a live connection | Messages are decrypted on a copy committed only after storing; the app reconnects after a storage error |
| 57 | Low | The PHP relay ignored `HUSH_TRUSTED_PROXIES` / `HUSH_FORWARDED_HEADER` defined in relay.config.php | Read again |
| 58 | Low | `onion = yes` in a settings file meant "off"; replacing a settings file kept its old permissions | Unknown values stop the relay; the file is written 0600 and renamed into place |
| 59 | Low | Turning on the app lock kept the vault key that had been stored in clear | A new key, everything re-encrypted in one transaction |
| 60 | Low | Deliveries over the live connection skipped the relay-wide cap on heavy work | They share it |
| 61 | Info | Page loads to unlisted paths, and app files missing from the cache, fell back to the network under a signed release | The verified app for every page load in scope; missing files fail closed |
| 62 | Info | The compatibility suite wasn't run by tests/run.sh; a Keystore failure fell back silently | Both run and reported |

### 2026-11-02: second review (of the fixes)

The same reviewer re-tested every fix with its proofs of concept; all held. It found three issues in the fixes and one gap, now fixed and re-tested with the same proofs of concept:

| # | Severity | Finding | Fix |
|---|---|---|---|
| 63 | Medium | Receiving on a copy of the contact (#56) could undo a Block, Verify, Delete or accept made at the same moment | Every change to a contact, by the user or by receiving, runs under the same per-contact lock |
| 64 | Low–Medium | Turning on the app lock while messages arrived could leave one stored with the old key | Delivery pauses and pending work finishes before re-encrypting; everything is read in one transaction |
| 65 | Low–Medium | Behind Tor, one anonymous client could use up the relay-wide budget for new live connections | Send connections on invite-only relays prove the join code; the relay-wide budget is charged only after every other check |
| 66 | Low | A move from the 0.5 database that kept failing (a full device) left the app on a blank screen | The reason is shown, and the old data is kept |
| 67 | Info | The send connection opened and closed together with the mail connection; a missing cached file was never fetched again | Its own random schedule; the service worker re-fetches the current signed release |

### 2026-11-13: audit of 0.7.1 and review of the owner dashboard (0.7.2, 0.8)

An internal audit of the 0.7.1 release (all test suites, the Go and PHP relays, the release signing and update path, the page security headers) before publishing it, then a review of the owner dashboard with its own tests (unit, race detector, mutation checks of the invite and key-rotation tests, and a browser test of the whole flow):

| # | Severity | Finding | Fix |
|---|---|---|---|
| 68 | Medium | PHP relay: a mailbox holding more than about 30 MiB (possible since 0.7.0's 48 MiB limit) made every fetch exceed a 128 MB `memory_limit`, so the owner received nothing until the mail expired. Anyone who knows a mailbox could cause it | Fetches return about 2 MiB at a time, like the Go relay (0.7.2) |
| 69 | Low | PHP relay: parallel deliveries to one mailbox could pass its 48 MiB limit | Deliveries to a mailbox are written one at a time (0.7.2) |
| 70 | Medium | Renewing a membership needed the current join code, so changing the code would have dropped every existing member after 180 days | Members renew with their mailbox secret alone (0.8) |
| 71 | Low | With single-use invites, the move to a new device would have sent the member's mailbox secret to any relay on the same host named in a scanned code | Only to the member's own relay's exact address (0.8) |
| 72 | Info | Owner requests answered differently with and without an owner, telling anyone with the address whether the relay was claimed | The same answer either way (0.8) |
| 73 | Low | In a browser, a page in the background stopped reconnecting to save battery, so popups while it was open (0.8, new) would have stopped once the connection dropped | With notifications on, the page stays connected in the background (0.8) |

Web Push (0.8, new) was designed against the same review: the relay contacts only the push services' own hosts over HTTPS (port 443, no redirects), so a made-up subscription can't make it reach anything else; the payload is fixed and carries nothing; subscriptions need the mailbox secret (and membership on an invite-only relay), are capped, and expire. The encryption was checked against an independent implementation (`http_ece`, used by pywebpush: `tests/push-check.py`) and the VAPID signature with Go's ECDSA verification.
