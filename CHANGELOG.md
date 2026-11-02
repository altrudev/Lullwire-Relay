# Changelog

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
