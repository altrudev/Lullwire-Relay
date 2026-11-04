# About Lullwire Relay

**Lullwire Relay** is an open-source, end-to-end encrypted messenger with voice and video calls, built to run on a relay you own. There are no accounts, no phone numbers and no app store, and nobody in the middle can read what you send.

## Purpose

Most messengers depend on one company's servers and its rules. Lullwire Relay makes it practical for anyone to run their own small, private relay (on a VPS, a spare phone or basic hosting), invite only the people they choose, and inspect every line of code involved. Encryption happens on each person's device; the relay only ever stores and forwards sealed envelopes.

## Components

| Component | Implementation | What it does |
|---|---|---|
| App | HTML, vanilla JavaScript, WebCrypto, WebCodecs, service worker | Keys, encryption, contacts, calls; installable as a web app (PWA) |
| Android app | Java WebView shell, no libraries (`android/`) | The same app bundled in a small APK: background delivery, Keystore-protected storage, screenshot blocking, no cloud backup |
| Go relay | One binary, Go standard library only (`cmd/lullwire-relay`) | Mailboxes, live delivery and call rooms over one WebSocket, private path, invite-only mode, setup wizard; serves the app |
| PHP relay | One file (`web/relay.php`), "lite" | Messages on ordinary shared hosting; no calls, no live connection, no new features |
| Protocol | [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | Signed prekeys and Double Ratchet, sealed envelopes, calls, recovery, device moves, signed releases |
| Tests | Go, Node.js, shell, Playwright, Android emulator | Crypto and relay checks, hardening, five-browser and on-device runs including video calls |

## What it does not promise

**Experimental, with no independent professional cryptographic audit.** It has been through several rounds of internal adversarial review (see the [audit log](SECURITY.md#audit-log)), but passing tests and internal reviews are not proof of production-grade security. Don't rely on it where a failure could put people in danger; use [Signal](https://signal.org) or [SimpleX](https://simplex.chat) for that.

The relay can see metadata: IP addresses, which mailbox receives mail, timing, approximate (padded) sizes, and that a call happened and for how long. Installed web apps only accept new code signed with the release key, but a fully compromised server can replace the service worker that enforces this; the Android app bundles a fixed copy. See [SECURITY.md](SECURITY.md).

Current limits: one active device per profile, no push notifications in the browser (the Android app delivers in the background), one-to-one calls, and message history kept only on the device that received it.

## Getting started

- **Use it:** open an invite link from someone who runs a relay, or install the Android app from [Releases](https://github.com/altrudev/Lullwire-Relay/releases).
- **Host it:** download the relay for your device from Releases and follow the [self-hosting guide](docs/SELF-HOSTING.md).
- **Try it locally:** `go build -o lullwire-relay ./cmd/lullwire-relay && ./lullwire-relay`, then open http://localhost:8080 in two browsers.

## Ownership and governance

- **Project:** Lullwire Relay (named Hush Relay until 0.5)
- **Creator, designer and maintainer:** Valentyn (Val) Rukhaylo, [ALTRU.dev](https://altru.dev) ("Code for Humanity")
- **Copyright:** © 2026 Valentyn Rukhaylo (ALTRU.dev); see [NOTICE](NOTICE)
- **Repository:** https://github.com/altrudev/Lullwire-Relay
- **First public version:** 0.3.0 (2026-10-31) · **Current:** 0.7.1 (2026-11-04)
- **License:** GNU AGPL v3.0 or later for original code and documentation; bundled libraries keep their own licenses ([LICENSES.md](LICENSES.md)); name and logo are not licensed as trademarks ([brand guide](assets/brand/README.md))
- **Contributions:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security reports:** [SECURITY.md](SECURITY.md); please never post exploitable issues publicly

No organization, foundation or third-party service sponsors, audits or endorses this software.
