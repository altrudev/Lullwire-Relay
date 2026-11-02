# Security

## Status

Lullwire Relay is **experimental and has not been audited by an independent security firm.** Each release has had internal adversarial review with working exploit scripts, and every confirmed finding was fixed with a regression test before release (see the audit log below). That is not a substitute for review by outside cryptographers.

Use it for everyday privacy, learning and experiments. If a bug could put you or the people you talk to at risk (activists, journalists, sources, people facing a hostile government), use [Signal](https://signal.org) or [SimpleX](https://simplex.chat).

## Reporting a vulnerability

Please report privately through GitHub's **Report a vulnerability** button (the Security tab of this repository). Don't open a public issue. Include steps to reproduce if you can. Fixed issues are listed in the audit log below, with credit if you want it.

## What it is designed to protect

| Threat | Protection |
|---|---|
| Relay operator reading messages | End-to-end encryption (Double Ratchet, AES-256-GCM) |
| Relay operator learning who sent a message | Sealed sender: a fresh ephemeral key per envelope |
| Relay operator learning exact message length | Padding to 1, 4, 16 or 32 KiB |
| Someone who later steals a device reading past captured traffic | Forward secrecy for message bodies (see limit 1) |
| Forged or tampered messages | Authenticated encryption bound to both identities and the header |
| Replayed messages or replayed old sessions | Ratchet counters, single-use session ids, authenticated timestamps |
| Relay operator opening or replacing the recovery backup | 66-bit random words, PBKDF2 600k, token-guarded slot |
| Unsolicited senders posing as your contacts | Unknown senders arrive as *requests*, marked unverified; safety numbers |
| Relay operator or network listening to calls | Per-call random key sent inside the ratchet; one AES-GCM key per direction; frames bound to type and sequence number |
| Replayed or reordered call frames | Strictly increasing per-direction sequence numbers, checked inside the authenticated data |
| A contact or relay steering your app into a call elsewhere | Calls are joined only on the caller's own relay host |
| Strangers using your relay as free storage | Invite-only mode (join code); only member mailboxes can receive mail or store recovery slots |
| Scanners recognising the server as a messenger | Private path with a plain front page; calls and messages are ordinary HTTPS to your server |
| Other Android apps reading your keys | App-private storage, no cloud backup, screenshots blocked in release builds |
| Abuse of a public relay | Per-client rate limits (real client address, also behind a proxy or tunnel), per-mailbox quotas, disk floor, expiry |

## Known limits (by design, for now)

1. **No prekeys.** Until a contact replies, the first messages of a session depend on both identity keys. Someone who records traffic and later steals an identity key can read those first messages and learn the sender of any recorded envelope. Ongoing conversations have forward secrecy.
2. **Key-compromise impersonation.** Someone who steals your identity key can pose as anyone *to you*.
3. **The relay sees metadata:** IP addresses, timing, which mailbox receives mail, the size bucket, and whether mail is waiting. Use a relay you trust, Tor, or a tunnel that hides client IPs if this matters.
4. **Web delivery.** Whoever serves the app's files can serve modified code. Pin an IPFS CID, self-host the app, or check `app.js` against a tagged release.
5. **Shared origins.** Browser storage is per origin. Don't host the app on an origin that also runs other people's code (for example, a shared cPanel domain with other apps).
6. **Device linking** uses a 12-digit comparison code (about 40 bits) inside a 10-minute window. Compare the code; never approve a request you didn't start.
7. **Invites are not signed.** If someone intercepts your invite, they can swap the mailbox in it, though not the key. Verify safety numbers once.
8. **Calls go through the caller's relay.** It can see that a call happened, when, for how long and roughly how much data it used. It can't see or hear the call. It does learn the caller's mailbox (the caller proves membership when opening the room), and when the callee uses the same relay it can usually link the two by timing. There is no peer-to-peer mode, so neither side learns the other's IP address.
9. **The private path is not a secret from the relay host or your network provider's view of your server.** HTTPS hides the path and content, but not the server's address or name. The join code, not the path, is what keeps strangers out.
10. **Android app updates are your responsibility.** There's no store to update it: check the APK's SHA-256 and signing-certificate fingerprint against the release page, and keep Android System WebView updated, since the app runs on it.
11. **One device per account.** Recovering or linking while another copy is still active leads to lost messages. Erase the old copy.
12. **Some sizes aren't hidden.** Messages are padded up to 32 KiB, but larger payloads (a profile being moved) and recovery slots travel at their real size, which hints at how many contacts you have.
13. **Recovery words share one salt.** The 6 words carry 66 bits and PBKDF2 runs 600,000 rounds, but the salt is the same for everyone, so a relay holding many recovery slots can test each guess against all of them at once. Fixing this needs a new recovery format.
14. **Sender details are protected by the outer layer only.** The sender's mailbox, relay and name inside an envelope are encrypted to you but not bound into the ratchet's authentication. This is safe while the outer layer stays confidential; a future protocol version should bind them.
15. **Invite links can be forwarded.** Anyone holding your link can add you and, on an invite-only relay, join it. The first 25 people are added as contacts; later ones arrive as requests. Make a new link from the invite screen if one spreads too far.
16. **No independent cryptographic review yet.**

## Deployment checklist

- Serve over HTTPS. Browsers refuse the crypto APIs otherwise.
- Keep `LULLWIRE_DATA` outside the web root unless you're on Apache with `.htaccess` enabled (`AllowOverride`); the relay can't detect an Apache that ignores `.htaccess`. Elsewhere, the relay refuses to start when the data folder is inside the web root.
- Behind a proxy on another machine, list it in `LULLWIRE_TRUSTED_PROXIES` so limits apply per real client. Local proxies and tunnels are trusted automatically.
- Keep anti-framing headers on: `web/.htaccess` (Apache) and `scripts/router.php` (`php -S`) send them. On Caddy or nginx, add `Content-Security-Policy: frame-ancestors 'none'`.
- Turn off access logs you don't need.
- Behind a Tor onion service, run the Go relay with `-onion`; otherwise every visitor shares one client identity for rate limits. Back up the onion service's key folder and keep it private.
- Use the private setup: `-path` and `-join-code` (`lullwire-relay -new-path` prints a pair). Share the app only through invites.
- If a proxy sits in front, make sure it passes WebSocket upgrades to `…/live` (Caddy and Cloudflare Tunnel do by default; nginx needs `proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";`).
- Android release builds: keep the signing key (`~/.lullwire-relay/release.jks`) offline and backed up, and publish the APK's SHA-256 and certificate fingerprint with each release.
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

