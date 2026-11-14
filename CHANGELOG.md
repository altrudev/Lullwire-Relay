# Changelog

## 0.8.1 (2026-11-14): sounds, message times and an easier move
- **Sounds:** a chime when a message arrives that isn't on screen, and ringing for incoming calls until they're answered or declined. On by default; **Settings → Sounds** turns them off. The Android app's notifications keep Android's own sounds
- **Message times:** a received message shows when it was **sent** (the sender's time, carried inside the encrypted message), not when this device got it. If it arrived much later (it waited at the relay while the device was off), the time it arrived is shown next to it. Times in the future are capped at now. Files too
- **Moving instead of a second profile:** **Create profile** first asks whether you already use Lullwire on another device, with **Move it here** as the main choice, since a new profile is a separate account that contacts of the old one won't reach. The move screen lists the steps, including how to use a screenshot when the other device has no camera
- Tests: a browser test of the new question, the move screen, chimes (and none for the open chat or with Sounds off), ringing until a call is declined, and sent/arrived times

## 0.8.0 (2026-11-14): owner dashboard, single-use invites and notifications
- **Notifications in the browser:** with **Settings → Notifications** on, a popup when a message or call arrives while the app is in the background or another tab (generic unless names are on); the app then stays connected in the background
- **Notifications while closed (Web Push, opt-in):** **Also when Lullwire is closed** asks the browser maker's push service to wake the app. The relay (`-push`, on by default, off by default with `-onion`) sends an encrypted, empty signal when mail arrives and the app isn't connected; the popup says "New message". Apple or Google learn when messages arrive, never who from or what. On iPhone and iPad it works from the Home Screen (iOS 16.4+). Only the push services' own hosts are contacted; subscriptions are capped, expire, and go when a member is removed
- **Owner dashboard** (Go relay), in **Settings → Owner dashboard**: run `lullwire-relay -owner-code` on the server and enter the code in the app. It shows members, activity today and this week, messages and data per day (last 14 days), waiting mail, recovery backups, live connections and calls, free disk, and the relay's version and uptime
- **Single-use invites:** the owner's **Invite someone** link lets one new person join, once, within 7 days. Open invites can be revoked
- **Shared join code on/off:** with it off, people join only through the owner's invites, and members' invite links add contacts without letting anyone join. Everyone already on the relay stays
- **Remove a member:** their membership and waiting mail are deleted, their connections closed, and they can't come back without a new invite
- **Restart** from the app: a graceful restart in place (same process), which also starts an updated relay program
- Members are anonymous ids to the relay (`SHA-256("lullwire-member|" + mailbox)`); the owner's app names the ones in its own contacts. Owner access is a token on one device, never in backups or moves; the relay keeps only its hash
- **Member key:** send connections now prove a key every member gets when joining or renewing, instead of the shared join code, and removing a member changes it. Apps before 0.8 keep working (their send connection falls back to HTTPS when the shared code is off)
- **Fix:** renewing a membership no longer needs the current join code, so changing the code can't drop existing members after 180 days
- Moving to a new device works with the shared code off: the member admits the two temporary mailboxes for an hour (at most 6 per hour), sending its mailbox secret only to its own relay's exact address
- Daily counts and last-seen times survive restarts (`stats.json`; member files record when they joined)
- `LEGACY` code for Hush Relay 0.5 is now planned for removal in 0.9
- Tests: owner claim, guessing limits, single-use invites, shared code off, member key and removal, temporary mailboxes, status counts, restart (Go unit tests, with the race detector and mutation checks); a browser test of the whole owner flow, including a profile move and a restart in place
- Tests: push subscriptions (allowed hosts, keys, limits, members only), signals (RFC 8291 encryption, VAPID signature, quiet period, 410 Gone, none while connected), checked against the independent `http_ece` library; a browser test of notification settings, background popups with and without names, and the service worker's popup for a push

## 0.7.2 (2026-11-13): PHP relay delivers large mailboxes in parts
- **Fix (PHP relay and single file):** a mailbox holding more than about 30 MiB (two files sent to someone offline, or deliberately filled by anyone who knows the mailbox) made every fetch run out of PHP's usual 128 MB `memory_limit`, so the owner received nothing until the mail expired after 14 days. The relay now hands out mail in parts of about 2 MiB, like the Go relay, and the app collects the rest on its next request. Introduced in 0.7.0 with the 48 MiB mailbox limit
- PHP relay: deliveries to one mailbox are written one at a time, so parallel uploads can't exceed its 48 MiB limit
- Tests: a mailbox of 12 pieces of 400 KB is delivered in parts on every relay (Go, PHP, single file)

## 0.7.1 (2026-11-04): reloads on hosts that redirect index.html
- **Fix:** on web hosting whose `.htaccess` redirects `…/index.html` to `…/` (a common "one address per page" rule), the installed app stored a redirected copy of its start page, and browsers refuse to open a page from one: every reload failed with a network error, including the sign-out after moving a profile to a new device. The app now stores a clean copy of each verified file. Found by running the browser test against the single file on lullwire.com
- Tests: the single-file suite runs behind such a redirect; the browser test recognises the deliberate relay probes over HTTP/2

## 0.7.0 (2026-11-04): file transfers, hidden single-file setup
- **Send files** with the paperclip in any chat: photos, documents, anything up to 16 MB. A file travels as pieces of 192 KiB, each an ordinary end-to-end encrypted message, so every relay (Go, PHP, single file) carries it like chat and keeps it until the recipient comes online. The recipient's app checks the whole file against its SHA-256 before showing it. Photos get a preview; **Save** downloads the file (browser) or asks where to keep it (Android). A file that couldn't be sent resumes from the first missing piece
- Files are stored encrypted on the device, each with its own key kept in the encrypted message record, so changing the app lock never has to re-encrypt them. Deleting a contact deletes their files
- Files are accepted from contacts only; message requests (strangers) can't fill your storage
- Relays keep up to **48 MiB** waiting per mailbox (was 8 MiB): room for a 16 MiB file for someone who is offline. Relays older than 0.7 still carry files up to about 8 MB in total waiting at a time
- **Hidden single-file setup:** rename `lullwire-relay.php` to something random before first use; its data folder takes the same name, so nothing in the address or on the server's disk says what it is
- Android app: saves received files through the system's "save to" picker
- Tests: files through the relay (pieces, reassembly, SHA-256, a 16 MiB file waiting for an offline recipient, tampered pieces refused); the browser test sends a photo and a 1 MB document and checks the preview, the bytes and Save; the single-file suite checks a renamed copy

## 0.6.2 (2026-11-04): connection status and instant reconnect
- **Connection status bar** under the header instead of a toast: "Connecting…", "Offline. Retrying in N s" with **Retry now**, or "No internet connection", then a brief "Connected". A reconnect that takes under 2.5 seconds isn't shown at all, so switching apps doesn't make it flicker
- **Reconnects at once** when you come back to the app after 15 seconds or more, when the network returns, when you open a chat, or when you tap Retry, instead of waiting out a retry delay that could reach a minute. A connection a sleeping phone may have left half-dead is replaced
- Long-polling requests time out (the relay answers within the wait it was asked for), so one a phone froze mid-way can't hang the app
- Browser test: offline and back (the message sent meanwhile arrives within seconds) and, on long-polling relays, Retry while the relay is unreachable
- Also includes 0.6.1 (not released separately)

## 0.6.1 (2026-11-04): one-file hosting, mailbox ids out of access logs
- **Single-file edition for web hosting:** `lullwire-relay.php` holds the app and the lite relay in one file. Upload it to any PHP host with HTTPS and open it; mail is kept above the public web folder when the host allows it. Built by `lullwire-release php` and `scripts/build-release.sh`
- **Mailbox ids no longer appear in URLs:** the app delivers with a new `send` action that carries the recipient's mailbox inside the request body instead of `?box=` in the address, so web server access logs (and hosts that keep them) can't link a sender's IP to a recipient's mailbox. Both relays still accept the old `put` for earlier apps, and the app falls back to it, once per relay, for relays older than 0.6.1
- `lullwire-relay init`: the "just testing" choice now says nobody else can reach it, and points to the single file for people without a domain or server
- `scripts/build-release.sh` refuses to sign files in `web/` that aren't committed
- Tests: `tests/run.sh --php-file` runs the whole suite against the single file in a mock hosting account; browser runs on PHP check the access log holds no mailbox; Android device test waits for each WebView instead of fixed sleeps

## 0.6.0 (2026-11-02): Lullwire Relay
- **New name: Lullwire Relay** (formerly Hush Relay). Binary `lullwire-relay`, Android package `dev.altru.lullwire` (installs next to Hush Relay; move your profile across with "From my other device"), `LULLWIRE_*` settings. Hush Relay 0.5 apps keep working with Lullwire: messages, calls, backups and 6-word recovery are compatible, and `HUSH_*` settings and old data folders are still read
- **Protocol v4**
  - Signed prekeys, replaced every 14 days: conversations open X3DH-style, so even a session's first messages get forward secrecy, and the outer layer is sealed to the prekey
  - Signed address cards (mailbox, relay, prekey) in invites and messages: a swapped mailbox in an intercepted invite is detected, and contacts follow an address change safely
  - The sender's mailbox, relay, name and card are bound into every message's authenticated data
  - Padding gets a random tail; large payloads and recovery slots are padded in 16 KiB steps
- **Encrypted storage on the device**: messages, contacts, ratchet state and keys are stored encrypted (AES-GCM, blinded indexes). On Android the key is held by the Keystore; anywhere, an optional **app lock** passphrase protects it. Identity keys are non-extractable at runtime. The 0.5 database is migrated once and deleted
- **8 recovery words** (88 bits) for new setups; 6-word sets still work and can be upgraded from Settings (the old slot is deleted)
- **One live connection**: the Go relay delivers mail over the same WebSocket as calls, and the app sends through it to contacts on the same relay. Optional **cover traffic** both ways. Long-polling remains as the fallback, with randomised timing
- **Android background delivery**: a foreground service keeps the connection while the app is closed (no Google services, no push servers); notifications show no names unless turned on
- **Signed web releases**: `lullwire-release keygen | sign | verify`; installed web apps run only releases signed with the pinned key and refuse forged, unsigned or older ones. Settings shows which code is running
- **Setup wizard**: `lullwire-relay init` asks a few questions, writes a settings file and prints the proxy, tunnel or Tor configuration and a hardened systemd unit
- Stricter page security policy (no inline styles; connections only to https/wss relays, plus `.onion` and localhost for development)
- Long chats load 100 messages at a time; deleting a contact deletes its messages too
- The PHP relay is now the "lite" relay: messages only, no new features
- `LEGACY` code paths for Hush Relay 0.5 are marked for removal in 0.8 (docs/PROTOCOL.md)
- Tests: protocol v4, vault and recovery tests; a 0.5 <-> 0.6 compatibility suite; live mail, cover traffic, wizard and release-tool tests in Go; browser tests for signed releases, migration from 0.5 and the app lock; a background-delivery step in the Android device test

## 0.5.0 (2026-11-01): calls, private relays and the Android app
- **Encrypted voice and video calls** through your own relay
  - WebCodecs (Opus 32 kbit/s, VP8 640×360 at 15 fps), audio worklets with a small jitter buffer, echo cancellation
  - A fresh 32-byte key per call, sent inside the ratchet; one AES-GCM key per direction, strictly increasing sequence numbers
  - Carried over the relay's HTTPS connection (a standard-library WebSocket at `/live`): no peer-to-peer link, no extra ports, no IP exposure between callers
  - Ringing, decline, busy, missed-call and duration notes in the chat; audio-only fallback when the camera is refused
- **Private relays** (Go relay)
  - `-path` serves the app, relay and calls under a secret path, with a plain front page everywhere else (`-cover` for your own)
  - `-join-code` makes the relay invite-only; invites carry the code so friends just tap the link
  - `-new-path` prints a random path and join code
- **Android app**: the web app bundled in a small APK (no app store, no Google services, no libraries)
  - Served from a private origin inside the app; camera, microphone, file picker, share, copy and backup-save bridges
  - Screenshots blocked and keys excluded from cloud backups in release builds; share an invite link to the app to open it
  - Built with the plain SDK tools (`android/build.sh`); a two-person device test with a video call runs on an emulator
- **Redesign**: light, professional interface; one-tap invites (link, share sheet or QR) that add both people as contacts; a paste-invite field on the welcome screen
- Fetching from a mailbox that hasn't joined an invite-only relay answers like an empty mailbox (only sending is refused)
- Tests: browser end-to-end run now covers invite links, an invite-only relay behind a private path and a full video call
- Security review of the new code: 13 findings fixed before release, including one high-severity issue in the Android app's link handling (see SECURITY.md, entries 26–38)
- Official logo, app icons (PWA and Android), README banner, social preview and an install-and-use guide
- Release builds of the Android app are signed by Valentyn Rukhaylo (ALTRU.dev); certificate SHA-256 `38:40:AF:64:FB:BB:D8:43:D6:A9:1F:7F:C0:F7:03:AF:AB:AD:32:4F:A0:8C:D4:24:A5:74:32:5E:00:CD:53:19`
- Copyright and NOTICE: © 2026 Valentyn Rukhaylo (ALTRU.dev); brand guide for the name and logo
- Full audit of the whole repository: 3 medium and 5 low-severity issues fixed before release (SECURITY.md, entries 39–47): join-code lockout, membership limits and expiry, invite-link auto-accept cap with "Make a new link", contact deletion, authenticated device-move acknowledgement, Android device-transfer exclusion
- Contributor License Agreement (CLA.md) and a pull request template; contributors keep their copyright
- Relay binaries for 10 platforms with SHA256SUMS (`scripts/build-release.sh`)

## 0.4.0 (2026-11-01): Go relay and Tor onion services
- New Go relay: one self-contained binary with the app built in, Go standard library only
  - Same API and data layout as `relay.php`; the two can share a data folder
  - In-memory long-poll wake-ups: 3,000 simultaneous live connections tested at about 80 MB
  - Builds for Linux (x86, ARM, ARMv7), Android, Windows, macOS and FreeBSD
  - Anti-framing headers, dotfile/data/source protection, refuses a data folder inside the served folder
- Tor onion-service mode (`-onion`): limits apply per mailbox because Tor hides client addresses
- Independent review of the Go relay: 4 confirmed issues and 9 smaller ones fixed with regression tests
  (onion limit bypass via forwarded headers, a lock stall on recovery lookups, memory exhaustion via large
  deliveries on small devices, abrupt shutdown); deliveries are now streamed and capped at about 2 MiB
- Both relays read a single configurable forwarded-address header (`X-Forwarded-For` by default)
- App accepts v3 `.onion` relay addresses over `http://`
- Self-hosting guide: Go relay, Tor onion service, hardened systemd unit
- Tests: Go unit tests (race detector), shared suite and four-browser run against both relays

## 0.3.0 (2026-10-31): first public release
- Live delivery (long-polling), messages arrive in about a second
- QR invites; scan with the camera or from a picture
- Move an account to a new device by QR, confirmed with a 12-digit code
- 6-word recovery backed by an encrypted slot on the relay
- Double Ratchet with forward secrecy, sealed sender, size padding
- Encrypted backup files (passphrase)
- IPFS publishing script; app refuses to run on shared-origin path gateways
- `serve.sh` + router for PHP's built-in server (phones, Pis, VPS)
- Two rounds of adversarial review; 20 issues fixed with regression tests (see SECURITY.md)
- Test suite: crypto core, relay API, server hardening, four-browser end-to-end
