<p align="center"><img src="assets/brand/banner.png" alt="Lullwire Relay: private chat, voice and video on a relay you own" width="100%"></p>

# Lullwire Relay, formerly Hush Relay

**A small, self-hostable, end-to-end encrypted messenger with voice and video calls. No accounts, no phone numbers, no app store.**

*Version 0.6 renamed the project; it still talks to Hush Relay 0.5 apps.*

[**Download**](https://github.com/altrudev/Lullwire-Relay/releases/latest) · [Install & use](#install) · [Host a relay](docs/SELF-HOSTING.md) · [Security](SECURITY.md) · [Protocol](docs/PROTOCOL.md)

Lullwire Relay is two pieces:

- **The app** is a web page (a PWA) made of plain HTML and JavaScript. You open it in a browser and can install it to your home screen, or install the **Android app**, which bundles the same code. All encryption happens there.
- **The relay** is a dumb mailbox. It stores encrypted envelopes until the recipient picks them up, and it can't read them or see who sent them. The main relay is a **single Go binary** with the app built in (standard library only, no dependencies); a **one-file PHP relay** (messages only) remains for shared hosting.

You run the relay yourself, on a spare Android phone, a $5 VPS, a Raspberry Pi or ordinary shared hosting. With a **private path and a join code** it looks like an ordinary website to everyone except the people you invite, and messages and calls travel as normal HTTPS traffic to your own server. A **Tor onion service** is optional, never required. You can also publish the app on IPFS.

> ⚠️ **Status: experimental and not independently audited.** The design uses standard building blocks (a Signal-style Double Ratchet on WebCrypto), but it has only had internal adversarial review ([audit log](SECURITY.md#audit-log)), not review by outside cryptographers. Use it for everyday privacy, learning and experiments. **If your safety depends on your messages** (activists, journalists, sources, people facing a hostile government), use [Signal](https://signal.org) or [SimpleX](https://simplex.chat) instead. See [SECURITY.md](SECURITY.md).

## Features

- **End-to-end encryption with forward secrecy from the first message:** conversations open against a signed prekey (X3DH-style) and then run a Double Ratchet, so a stolen device can't decrypt messages captured earlier.
- **A sealed sender:** the relay can't tell who sent a message. Messages are padded to size classes with a random tail, so the relay learns only a coarse length.
- **Signed addresses:** invites and messages carry a card signed by your identity key, so nobody can swap your mailbox in an intercepted invite, and contacts follow you safely if your address changes.
- **Encrypted on the device:** messages, contacts and keys are stored encrypted. On Android the key sits in the phone's secure Keystore; anywhere, an optional **app lock** passphrase protects them.
- **Voice and video calls:** encrypted end to end with a fresh key per call, carried over your relay's HTTPS connection. No peer-to-peer link, so neither side sees the other's IP address.
- **Private relay:** a hidden path with a plain front page, and invite-only mode so strangers can't use your server. Invite links carry the join code, so friends just tap and start.
- **Android app:** a small APK (no app store, no Google services) built with the plain SDK tools; it blocks screenshots and keeps keys out of cloud backups.
- **Live delivery over one connection:** a single long-lived HTTPS (WebSocket) connection to your relay carries messages in both directions, like any mainstream chat app. Optional **cover traffic** hides when you're actually sending. Messages wait up to 14 days on the relay while you're offline.
- **Background delivery on Android:** messages and calls arrive while the app is closed, with no Google services or push servers. Notifications show no names unless you turn them on.
- **Signed releases:** once installed, the web app only switches to new code signed with the developer's release key (fingerprint `BC36A70831DA314F`, shown in the app under **Settings → App code**).
- **No sign-up:** your identity is a key generated on your device. You add contacts by QR code or invite link.
- **Safety numbers** to check that nobody is in the middle. Strangers who message you arrive as *requests* until you reply.
- **Move your account by QR:** scan a one-time code from your old device and approve after matching a 12-digit code.
- **8 recovery words:** an encrypted backup kept on your relay, so you can get your account back on any device. The relay can't open it. (6-word sets from earlier versions still work and can be upgraded in Settings.)
- **Different relays talk to each other:** each person can use a different relay, in any country.
- **No dependencies:** vanilla JS, WebCrypto and WebCodecs in the browser; a Go relay built only on the standard library (or one PHP file); a Java Android shell with no libraries. Three small vendored libraries handle QR codes and the wordlist.

## Install

<p align="center"><img src="assets/brand/install-and-use.png" alt="How to install and use Lullwire Relay" width="540"></p>

**To chat** (everyone you invite), pick one:

| | How | Notes |
|---|---|---|
| **Android app** | Download `lullwire-relay-<version>.apk` from [Releases](https://github.com/altrudev/Lullwire-Relay/releases/latest) and open it | No store. Check the SHA-256 from the release; official builds are signed by Valentyn Rukhaylo (ALTRU.dev), certificate `38:40:AF:64:…:00:CD:53:19` ([full fingerprint](docs/SELF-HOSTING.md#android-app)) |
| **Web app (PWA)** | Open an invite link, then **Install** or **Add to Home Screen** | Android, Windows, Linux, ChromeOS, macOS; on iPhone use Safari's **Add to Home Screen** |
| **Any browser** | Just open the invite link | Calls need a recent Chrome, Edge, Firefox or Safari |

**To host** (one person per group), the easy way: download **`lullwire-relay.php`** from [Releases](https://github.com/altrudev/Lullwire-Relay/releases/latest), upload that one file to any web hosting with PHP and HTTPS (cPanel and most shared hosts), and open `https://your-site/lullwire-relay.php` in a browser. That's the whole setup: create your profile there and send invites. It does messages and recovery; for voice and video calls, run the Go relay instead: download it for your device (Linux x86/ARM, Raspberry Pi, Windows, macOS), run `./lullwire-relay init` and follow the steps it prints. The Go relay needs a domain with HTTPS in front of it (Caddy, nginx, Cloudflare Tunnel or Tor); on its own it only answers on your computer. The [self-hosting guide](docs/SELF-HOSTING.md) covers every option.

## Quick start (local, 1 minute)

```bash
git clone https://github.com/altrudev/Lullwire-Relay.git lullwire-relay
cd lullwire-relay
go build -o lullwire-relay ./cmd/lullwire-relay && ./lullwire-relay     # Go 1.22+
# or, with PHP 7.4+:  ./scripts/serve.sh
```

Open http://localhost:8080 in two different browsers (or one normal and one private window). Create a profile in one, tap **Invite someone** and open that link in the other. Then chat, or start a call from the chat header.

## Put it on the internet

Browsers only allow the app's encryption on `https://` (or `localhost`), so a public relay needs HTTPS. Pick one:

| Where | Effort | Notes |
|---|---|---|
| **Shared hosting, one file** (easiest) | Easy | Upload `lullwire-relay.php`, open it. Messages only, no calls. [Guide](docs/SELF-HOSTING.md#shared-hosting) |
| **Your own VPS, private** (recommended for calls) | Medium | Hidden path + join code: looks like a plain website, calls included. [Guide](docs/SELF-HOSTING.md#private-setup-recommended) |
| **Tor onion service** (optional, any Linux device or phone) | Medium | No domain, tunnel company or open ports; the location stays hidden. [Guide](docs/SELF-HOSTING.md#tor-onion-service) |
| **Spare Android phone** (Termux + Cloudflare Tunnel) | Medium | Free and always on while plugged in. [Guide](docs/SELF-HOSTING.md#android-phone-as-the-relay) |
| **VPS** (Debian/Ubuntu + Caddy) | Medium | Most reliable, about $5/month. [Guide](docs/SELF-HOSTING.md#vps) |
| **App on IPFS**, relay anywhere above | Advanced | Anyone can mirror the app. [Guide](docs/SELF-HOSTING.md#ipfs) |

The relay address gets baked into every invite, so **keep it stable.** A tunnel URL that changes on every restart will break your contacts' links.

## Using it

1. **Create a profile.** Pick a display name. Opened from an invite link, everything else is filled in.
2. **Invite someone.** Tap **Invite someone** and share the link (any messenger, email or SMS) or let them scan the QR. They open it, pick a name, and you're connected.
3. **Verify once.** Tap the yellow bar in the chat and compare the safety code in person or on a call, then tap **They match**.
4. **Call.** The phone and camera buttons in the chat header start an encrypted voice or video call.
5. **Turn on recovery words** in **Settings** and write the 8 words down. They're the only thing you need to get your profile back.
6. **New phone?** On it, choose **From my other device**. On the old one, tap **Scan**, check the 12-digit code matches and approve. The profile moves over, and the old device signs out.

On Android you can also install the [app](docs/SELF-HOSTING.md#android-app); paste an invite link on its welcome screen, or share the link to it.

Links opened from outside the app (a web page, another app, a shared text) always ask before adding a contact, and can never start a profile move: move codes are only accepted from **Scan**.

## Repository layout

```
cmd/lullwire-relay/ Go relay: one binary, app built in, standard library only
  live.go       WebSocket call rooms (RFC 6455, standard library)
  mail.go       live mail over the same WebSocket
  init.go       the setup wizard (lullwire-relay init); config.go reads its settings file
cmd/lullwire-release/ signs the web app (release key, release.json)
web/            the app (and the PHP relay)
  index.html    UI (style.css: its stylesheet)
  app.js        crypto core, encrypted vault + app logic (also loadable in Node for tests)
  call.js       encrypted calls: WebCodecs (Opus, VP8) + AES-GCM frames
  worklet.js    audio capture and playback for calls
  relay.php     the PHP mailbox relay, "lite": messages only, no new features (same API and data layout)
  embed.go      tells the Go build which app files to include
  config.js     optional default relay URL (used for IPFS builds)
  sw.js         offline support; runs only code signed with the release key (release.json)
  vendor/       qrcode-generator (MIT), jsQR (Apache-2.0), BIP39 wordlist (MIT)
scripts/
  serve.sh      run app + relay with PHP's built-in server
  router.php    keeps the data folder private under php -S
  publish-ipfs.sh
android/        Android app: Java WebView shell, no libraries; build.sh uses the plain SDK tools
assets/brand/   logo, icons, banner, social preview, install guide (and render.py to rebuild them)
tests/
  run.sh        full test suite against a throwaway relay
  android/      two-person device test on an emulator (app + browser, video call)
  core.test.js  crypto, ratchet, protocol v4, vault, relay API, recovery, linking
  compat.test.js  Lullwire 0.6 <-> Hush Relay 0.5 (frozen copy in fixtures/)
  e2e.py        multi-browser test (Playwright); sw.py: signed releases in the browser
docs/
  SELF-HOSTING.md  PROTOCOL.md  RELEASING.md
```

## Documentation

- [Project overview, scope and status](ABOUT.md)
- [Protocol and threat assumptions](docs/PROTOCOL.md)
- [Self-hosting and deployment](docs/SELF-HOSTING.md)
- [Security limitations and vulnerability reporting](SECURITY.md)
- [Contributing and local test procedure](CONTRIBUTING.md)
- [Third-party attribution and licensing](LICENSES.md) · [NOTICE](NOTICE) · [Brand guide](assets/brand/README.md)
- [Release history](CHANGELOG.md)

## Tests

```bash
./tests/run.sh --go     # Go relay: gofmt, vet, unit tests (race-safe), then the shared suite (needs go + node 20+)
./tests/run.sh          # PHP relay (needs php + node 20+)
# add --e2e for five real browsers incl. an encrypted video call (pip install playwright && playwright install chromium)
SERIAL=emulator-5554 ./tests/android/run.sh   # Android app on an emulator (needs the Android SDK)
```

## Limits

- **Calls are one-to-one** and go through the caller's relay, which sees that a call happened, how long it lasted and roughly how much data it used, but not what was said or shown.
- **One active device per account.** Linking moves an account; it doesn't add a second device.
- **Message history stays on the device that received it.**
- **The relay operator sees metadata:** IP addresses, timing, size bucket and which mailbox gets mail. They can't see content or senders.
- **The web delivery problem:** once installed, the web app only accepts code signed with the release key, but a fully compromised server can still replace the service worker that enforces this. The Android app and a pinned IPFS CID don't have this problem.
- **No push notifications in the browser.** The Android app delivers in the background; in a browser, messages arrive while the app is open.

## Contributing

Issues and pull requests are welcome, especially security review. Contributors agree to the [Contributor License Agreement](CLA.md) once, on their first pull request; you keep your copyright. Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright © 2026 Valentyn Rukhaylo (ALTRU.dev).

Original Lullwire Relay code and documentation are licensed under the **GNU Affero General Public License v3.0 or later** (SPDX: `AGPL-3.0-or-later`). The complete license is in [LICENSE](LICENSE). For hosted modified versions, AGPL section 13 may require providing the corresponding source to network users; see [LICENSES.md](LICENSES.md) for an overview. AGPL permits commercial use provided its terms are followed.

Vendored components remain under their respective MIT or Apache-2.0 terms, detailed in [LICENSES.md](LICENSES.md) and the accompanying notice files. The "Lullwire Relay" name and logo are not licensed as trademarks: forks that ship modified builds need their own name and icon ([brand guide](assets/brand/README.md)). No separate proprietary license is granted by this repository; commercial licenses are available from the maintainer.

## Author

<img src="assets/brand/logo-mark-512.png" alt="" width="56" align="left">

**Lullwire Relay** is created, designed and maintained by **Valentyn (Val) Rukhaylo**, [ALTRU.dev](https://altru.dev) — *Code for Humanity*.<br>
Issues, ideas and security reports are welcome.
<br clear="left">
