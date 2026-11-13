# Hosting a Lullwire Relay

This guide explains what a relay is, why it needs a web address, and exactly how to set one up. If you only want to chat, you don't need any of it: open the invite link someone sent you.

- [How it works](#how-it-works)
- [Choose how to host](#choose-how-to-host)
- [Option A: web hosting, one file (easiest)](#option-a-web-hosting-one-file)
- [Option B: your own server, with calls](#option-b-your-own-server-with-calls)
- [Hidden setup, for people at risk](#hidden-setup-for-people-at-risk)
- [Troubleshooting](#troubleshooting)
- [Advanced: Tor, a spare phone, IPFS, the Android app](#advanced)

## How it works

Lullwire Relay has two parts:

```
   Your phone or computer                                  Your contact's phone or computer
 ┌────────────────────────┐                              ┌────────────────────────┐
 │  THE APP               │     sealed envelopes         │  THE APP               │
 │  encrypts and decrypts │ ───────────►  RELAY  ──────► │  encrypts and decrypts │
 │  everything            │ ◄──────────  (mailbox) ◄──── │  everything            │
 └────────────────────────┘                              └────────────────────────┘
        everyone uses this               one person hosts this for a group
```

- **The app** is what everyone uses: a web app that opens in any browser (and can be installed like an app), or the Android app. All encryption happens there. Your keys never leave your device.
- **The relay** is a mailbox at a web address. It holds sealed envelopes until the recipient's app collects them (up to 14 days), and carries calls on the Go relay. It cannot open envelopes, see who sent them, or read anything you send.

**The one requirement: the relay must be at an `https://` address that everyone you invite can reach.** Two reasons:

1. **Browsers only allow the app's encryption on `https://` pages.** A plain `http://` address (or an IP address without a certificate) won't run the app.
2. **Your devices find each other through the relay.** Phones and home computers can't be reached from the internet directly: home routers and mobile networks block incoming connections. That's why the relay lives somewhere that *can* be reached, on web hosting or a server, and everyone's app connects out to it.

So someone in your group needs either **web hosting** (the kind used for a website or blog) or **a small server**. Everyone else only needs the app.

Each person can use a different relay: contacts on different relays still message each other. Your relay's address travels inside your invites, so the people you invite connect to it without typing anything.

**What the relay's operator (and the hosting company) can see:** that messages arrive for a mailbox (a random code, not a name), when, from which IP addresses, and roughly how big they are. **What they can't see:** content, files, call audio or video, names, who sent a message, or who your contacts are.

## Choose how to host

| | **A. Web hosting, one file** | **B. Your own server (Go relay)** |
|---|---|---|
| **You need** | Web hosting with PHP 7.4+ and HTTPS (cPanel and most shared hosts) | A Linux server (VPS) and a domain name pointing to it |
| **Typical cost** | A few dollars a month, or hosting you already have | About $5 a month, plus the domain |
| **Setup** | Upload one file, open it in a browser: 5 minutes | Download the relay, run a setup wizard, install Caddy: 30 minutes, some command line |
| **Chats, files (up to 16 MB), recovery words** | ✓ | ✓ |
| **Voice and video calls** | ✗ | ✓ |
| **Invite-only (strangers can't use your relay)** | ✗ (they can't read anything, but could leave mail) | ✓ join code |
| **Delivery** | Within about a second, while the app is open (long-polling) | Instant (one live connection) |
| **Receive calls from contacts on a Go relay** | ✓ | ✓ |
| **Good for** | Families, friends, small groups | Groups that want calls; organisations |

**Not possible: a relay on your own computer or phone with nothing else.** As explained above, other people can't reach a device at home unless the router lets them in. The relay program *can* run on any computer, but on its own it only answers on that computer, and invites made there point at `localhost`, which nobody else can open. If you want to use a computer or phone you own anyway, it needs a tunnel or Tor in front of it: see [Advanced](#advanced).

---

## Option A: web hosting, one file

The single-file relay is the app and the relay in **one file**, `lullwire-relay.php`. It does messages, files and recovery. It doesn't do calls (PHP on shared hosting can't hold the live connections calls need).

### What you need

- **Web hosting with PHP 7.4 or newer.** Almost every cPanel host qualifies. In cPanel, *Select PHP Version* or *MultiPHP Manager* shows the version.
- **HTTPS on your domain.** Most hosts include free certificates (cPanel's *SSL/TLS Status* or *AutoSSL*). Open `https://yourdomain` in a browser: a padlock means you're ready.
- A way to upload a file: cPanel's **File Manager** is enough.

### Step by step

1. **Download** `lullwire-relay.php` from the [releases page](https://github.com/altrudev/Lullwire-Relay/releases/latest). Optional: check it against `SHA256SUMS` from the same page (`sha256sum lullwire-relay.php`).
2. **Choose its name before you upload it.** The name becomes part of your relay's address and of every invite, so it can't change later.
   - Keep `lullwire-relay.php` for an ordinary setup, or
   - rename it to something random, like `k7q4mxp2ab.php`, so nobody can find it without an invite (see [Hidden setup](#hidden-setup-for-people-at-risk)).
3. **Upload** it to your website's public folder: in cPanel, **File Manager → `public_html`** (or the folder of the domain or subdomain you want to use) **→ Upload**. That's the only file you need.
4. **Open** `https://yourdomain/lullwire-relay.php` (with your file's name) in a browser. It opens the app.
5. **Create your profile** there: pick a display name. The relay address is filled in for you.
6. **Invite people:** tap **Invite someone** and send the link by any messenger, email or text, or let them scan the QR code. They open it, pick a name, and you're connected. The link carries your relay's address, so they don't set anything up.
7. **Turn on recovery words** (Settings) and write the 8 words down. They restore your profile on a new device.

That's all. There's nothing to configure and no database.

### What it creates on your hosting

The first time someone uses it, the file creates one folder for waiting mail, named after the file: `lullwire-relay-data` (or `k7q4mxp2ab-data` for `k7q4mxp2ab.php`). It puts that folder **above** your public web folder (in your hosting account's home), where nothing on the web can reach it. If the host doesn't allow that, it puts it next to the file and locks it with an `.htaccess` rule, which Apache and LiteSpeed honour. To choose the folder yourself, put a `relay.config.php` next to the file containing `<?php define('LULLWIRE_DATA', '/home/you/somewhere');`.

The folder only ever holds sealed envelopes (deleted once collected, or after 14 days), encrypted recovery backups, and rate-limit counters.

### If your website has its own security headers

If your site's `.htaccess` sets a `Content-Security-Policy` or `Permissions-Policy` for every page (many security guides suggest it), those headers also reach the relay page and override the app's own policy. You'd see: **Scan** can't use the camera, the app can't be installed, and contacts on other relays can't be reached. Add this at the end of the `.htaccess` in the same folder as the relay file (use your file's name if you renamed it):

```apache
<Files "lullwire-relay.php">
  <IfModule mod_headers.c>
    Header always set Content-Security-Policy "frame-ancestors 'none'"
    Header always unset Permissions-Policy
  </IfModule>
</Files>
```

The rest of your site keeps its headers. The app brings its own strict policy, so it doesn't need yours. This works on Apache and LiteSpeed (cPanel); a `SetEnvIf Request_URI` exception doesn't work on LiteSpeed. Check it with `curl -sI https://yourdomain/lullwire-relay.php/`: the only `content-security-policy` line should be `frame-ancestors 'none'`.

### If you deploy your website with a sync tool

Tools that mirror a folder onto your hosting (for example `rsync --delete`, or a "deploy" button that replaces the whole site) will delete `lullwire-relay.php`, because it isn't part of your site's files. Exclude it (`--exclude=/lullwire-relay.php`). Your mail survives either way, because it's in the data folder outside the web folder, but the relay stops working until the file is back.

### Updating

Upload the new release's `lullwire-relay.php` **over the old one, under the same name**. The address is part of every invite, so it must not change. Installed apps pick up the new version on their next start. They only accept versions signed with the release key, so a tampered file is refused.

### Good to know

- **Capacity:** every open app keeps one request waiting at the relay for up to 20 seconds. Shared hosts limit how many PHP requests run at once, which is plenty for a family or a group of friends; for more people, use Option B.
- **Logs:** your hosting keeps access logs. Since version 0.6.1 they no longer contain mailbox codes, only IP addresses and times. In cPanel → **Raw Access** you can turn off log archiving.
- **Limits** (in `relay.php`'s constants if you build from source): 120 deliveries per minute per visitor, 48 MiB or 500 messages waiting per mailbox, 5 new recovery backups per visitor per day; it stops accepting data when less than 256 MiB of disk is free.
- **nginx hosting:** the app is served at `…/lullwire-relay.php/` (with a slash), which needs PHP's "path info". Apache and LiteSpeed (cPanel) do this by default; on nginx it needs `fastcgi_split_path_info`.
- **From the source folder instead:** upload the contents of `web/` (including `relay.php`) to a folder such as `public_html/lullwire/`, ideally with a `relay.config.php` pointing `LULLWIRE_DATA` outside `public_html`, and open `https://yourdomain/lullwire/`.

---

## Option B: your own server, with calls

The Go relay is one program (no dependencies) with the app built in. It adds **voice and video calls**, instant delivery over one live connection, and **invite-only** mode. It runs on a small Linux server (VPS), behind **Caddy**, which gets the HTTPS certificate automatically.

### What you need

- **A VPS** with Debian or Ubuntu: the smallest plan of any provider (1 CPU, 1 GB) is enough for a group, about $5 a month.
- **A domain name** (or a subdomain of one you own), for example `chat.example.com`.
- About 30 minutes and a terminal (SSH into the server).

### Step by step

1. **Point the domain at the server.** In your domain's DNS settings, add an **A record**: name `chat` (for `chat.example.com`), value: your server's IP address. It can take a few minutes to work.
2. **On the server, install Caddy** (it handles HTTPS by itself):
   ```bash
   sudo apt update && sudo apt install -y caddy
   ```
3. **Download the relay** for your server from the [releases page](https://github.com/altrudev/Lullwire-Relay/releases/latest) (`lullwire-relay-<version>-linux-amd64` for most servers, `-linux-arm64` for ARM) and install it:
   ```bash
   sudo install -m 755 lullwire-relay-*-linux-amd64 /usr/local/bin/lullwire-relay
   sudo useradd -r -m -d /opt/lullwire lullwire
   ```
4. **Run the setup wizard** as that user, and answer its questions:
   ```bash
   sudo -u lullwire lullwire-relay init
   ```
   Choose **1** (your own domain), type your domain, and say **yes** to a private relay. It writes a settings file and prints exactly what to do next: a Caddy block, a systemd service and your relay's address, which includes a secret path such as `https://chat.example.com/k7q4mxp2ab/`.
5. **Do what it printed:** put the Caddy block in `/etc/caddy/Caddyfile`, save the service file, then:
   ```bash
   sudo systemctl reload caddy
   sudo systemctl enable --now lullwire-relay
   ```
6. **Open your relay's address** (the one the wizard printed) in a browser, create your profile, and send invites from there. Calls work from the chat header.

A complete Caddy block looks like this:

```
chat.example.com {
    reverse_proxy 127.0.0.1:8080
    log {
        output discard     # don't keep IP logs you don't need
    }
}
```

### The private setup (recommended)

With a **private path** and a **join code** (the wizard sets both), the relay looks like an ordinary website to everyone except the people you invite:

- **The front page** (`https://chat.example.com/`) shows a plain "nothing here" page; any other address gives a normal 404. The app lives under the secret path.
- **The join code** makes the relay invite-only. Your invites carry it, so people you invite never type it; strangers who find the address can't create a mailbox or store anything.
- **Calls** travel over the same HTTPS connection, so to a network observer a call looks like any other secure connection to a website. No extra ports, no peer-to-peer traffic: callers never see each other's IP address.

To set them by hand: `lullwire-relay -new-path` prints a random path and code; use them with `-path` and `-join-code`.

### The owner dashboard

As the person who runs the relay, you can see how it's used and manage it from your app: **Settings → Owner dashboard**.

1. On the server, run the relay program with its usual settings plus `-owner-code`, as the same user that runs the relay:
   ```bash
   lullwire-relay -config /etc/lullwire-relay.conf -owner-code   # or: -data /path/to/data -owner-code
   ```
   It prints a code that works once, for 30 minutes. The running relay doesn't need a restart.
2. In the app, open **Settings → Owner dashboard**, enter the code and tap **Make this device the owner**.

The dashboard shows how many people use the relay and how actively, messages and data per day, waiting mail, storage and live connections. From it you can:

- **Invite people one at a time.** Your **Invite someone** link now lets one new person join, once, within 7 days; open invites are listed and can be revoked.
- **Switch the shared join code off.** Then people join only through your single-use invites, and links your members share add them as contacts without letting anyone join. Everyone already on the relay stays.
- **Remove someone.** Their account here and their waiting mail are deleted and they're disconnected; they can't come back without a new invite from you (or the shared code, if it's still on).
- **Restart the relay.** It restarts in place, which also starts an updated program if you replaced the file.

Members appear under anonymous ids; your app shows names for the people in your own contacts. Names never reach the relay. Owner access belongs to one device and isn't included in backups or moves: on a new phone, run `-owner-code` again (a new code replaces the old owner device). The dashboard needs the Go relay; the single PHP file doesn't have it.

**Calls and bandwidth:** a video call uses about 0.7 Mbit/s in each direction per person, all through the relay. The smallest VPS handles several calls at once.

**Moving from the single file:** point `-data` at the old data folder; waiting mail and recovery backups carry over.

### Settings

`lullwire-relay init` writes a settings file (`~/.config/lullwire-relay/relay.conf`, mode 0600) of `name = value` lines using the flag names below. Priority: command-line flags, then `LULLWIRE_*` environment variables, then the settings file, then defaults. Use `-config /path/relay.conf` (or `LULLWIRE_CONFIG`) for a file elsewhere.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `-addr` | `LULLWIRE_ADDR` | `127.0.0.1:8080` | Listen address. Keep it on 127.0.0.1 behind Caddy, nginx, a tunnel or an onion service. |
| `-data` | `LULLWIRE_DATA` | `~/.lullwire-relay-data` | Waiting mail and recovery backups (created with mode 0700). |
| `-path` | `LULLWIRE_PATH` | none | Private path for the app, relay and calls, e.g. `/k7q4mxp2/`. Every other address shows a plain front page. |
| `-join-code` | `LULLWIRE_JOIN_CODE` | none | Invite-only mode: only people with the code can get mail here. It travels inside your invites. |
| `-cover` | `LULLWIRE_COVER` | built in | Your own HTML file for the front page. |
| `-new-path` | | | Print a random `-path` and `-join-code`, then exit. |
| `-web` | `LULLWIRE_WEB` | built in | Serve the app from a folder instead (for example a custom `config.js`). |
| `-trusted-proxies` | `LULLWIRE_TRUSTED_PROXIES` | none | Proxy IPs on *other* machines allowed to report client addresses (local proxies are trusted automatically). |
| `-forwarded-header` | `LULLWIRE_FORWARDED_HEADER` | `X-Forwarded-For` | Header the proxy uses for the client address (`CF-Connecting-IP` behind Cloudflare Tunnel). |
| `-onion` | `LULLWIRE_ONION=1` | off | Tor mode: limits apply per mailbox, because Tor hides client addresses. |
| `-config` | `LULLWIRE_CONFIG` | `~/.config/lullwire-relay/relay.conf` | Settings file. |

The relay refuses to start if its data folder is inside a served folder. It protects small machines on its own: at most 128 uploads or deliveries at once, about 2 MiB of mail per fetch, and a clean shutdown that answers waiting connections first. Abuse limits match the single file (120 deliveries per minute per client, 48 MiB waiting per mailbox, 6 live connections per client, a 256 MiB free-disk floor).

**nginx instead of Caddy** (inside your HTTPS server block; the `Upgrade` lines carry calls and live mail):

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 120s;
}
```

**Coming from Hush Relay?** `HUSH_*` environment variables, an existing `~/.hush-relay-data` folder and a `relay.config.php` that defines `HUSH_DATA` keep working.

---

## Hidden setup, for people at risk

> ⚠️ **Read this first.** Lullwire Relay is experimental and **has not been independently audited.** If your life or freedom depends on your messages (activists, journalists, their sources, people facing a hostile government), use [Signal](https://signal.org) or [SimpleX](https://simplex.chat), ideally over [Tor](https://www.torproject.org). The steps below make a relay harder to find. They don't make the app safer to use under surveillance.

**What helps:**

- **Host outside your country,** with a hosting company that doesn't answer to your government, and a domain name that says nothing about you or the app.
- **Give the file a random name** before first use (`k7q4mxp2ab.php` rather than `lullwire-relay.php`). Its data folder takes the same name. Then:
  - Nobody finds the relay without an invite: visitors to your website see only your website.
  - A network observer (your internet provider) sees only that you connect to that website, with HTTPS like any other. The file name is inside the encrypted part of the connection.
  - The relay sends nothing that identifies it unless someone opens its exact address.
- **On your own server,** use the private path, a join code and a cover page of your own (`-cover`), so the server looks like an ordinary small website.
- **No phone number, no email, no app store:** nothing ties a profile to your identity. Install the Android app from the release file, or use the web app.
- **Verify safety codes** with each contact in person, so nobody can sit in the middle.
- **Turn on the app lock** (Settings) and recovery words. Keep the words somewhere safe that isn't the phone.

**What it can't hide:**

- **Your hosting company and anyone with access to the server** can see the file, its contents and the data folder, and can read the app's code. They still can't read messages or files, which are end-to-end encrypted, but they can tell what the file is.
- **Anyone holding an invite link** can find the relay: the link contains its address. Treat invites as private.
- **The relay and the host see IP addresses and timing.** To hide your IP from them, connect through Tor or a trustworthy VPN.
- **The app shows its name** to anyone who opens the relay's address; it can't be renamed without breaking the release signature.
- **A phone that's taken from you** shows the app. The app lock protects its contents.

---

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| **"That page isn't here"** or a 404 at your relay address | Check the address against the file name exactly, including `.php`. |
| **A list of files, or the PHP code** instead of the app | PHP isn't running for that folder. Check the PHP version in cPanel and that the file ends in `.php`. |
| **"This site can't provide a secure connection"** or no padlock | HTTPS isn't set up for that domain. Turn on AutoSSL or Let's Encrypt in your hosting panel and wait a few minutes. |
| **No call buttons in chats** | Your own relay is the single file, which doesn't do calls. Calls need [Option B](#option-b-your-own-server-with-calls). Calls run through the caller's relay, so a contact on a Go relay can still call you. |
| **"Offline. Retrying in N s"** bar | Your phone or computer lost its connection, or the relay can't be reached. Tap **Retry now**. If it stays, open the relay's address in a browser to check it's up. |
| **Scan doesn't open the camera; the app can't be installed** | Your website's own security headers reach the relay page: see [If your website has its own security headers](#if-your-website-has-its-own-security-headers). |
| **The relay disappeared after updating my website** | Your deploy tool deleted the file: see [If you deploy your website with a sync tool](#if-you-deploy-your-website-with-a-sync-tool). Upload it again under the same name. |
| **A file says "not sent, tap to retry"** | The relay refused it, usually because the recipient's mailbox is full (they've been offline a long time) or their relay is older than 0.7 (8 MB of waiting mail). Tap to resume once they've been online. |
| **The Go relay works on the server but nobody else can open it** | It listens only on `127.0.0.1` by design. Put Caddy or nginx in front with your domain (step 5 of Option B). |
| **"This relay is invite-only"** | Open an invite link from someone who uses it (it carries the join code), or enter the join code under **Advanced** on the welcome screen. |

---

## Advanced

### Tor onion service

An onion service gives a relay a `.onion` address with **no domain, no hosting and no open ports**, and hides where the relay physically is. Tor connects outward, so it works on a computer at home behind any router. The catch: people need **Tor Browser** to open it.

On any Linux computer (an old laptop, a Raspberry Pi, a VPS):

```bash
sudo apt install tor
# add to /etc/tor/torrc:
#   HiddenServiceDir /var/lib/tor/lullwire/
#   HiddenServicePort 80 127.0.0.1:8080
sudo systemctl restart tor
sudo cat /var/lib/tor/lullwire/hostname      # your address: <56 characters>.onion
./lullwire-relay -onion -join-code <code>    # lullwire-relay -new-path makes a code
```

- **Back up `/var/lib/tor/lullwire/`:** it holds the address's private key.
- **Always use `-onion` and a join code:** behind Tor every visitor looks the same, so limits apply per mailbox and the join code keeps strangers out.
- **Tor Browser forgets site data when it closes,** including your keys: turn on recovery words and sign back in each session, or offer both an onion and an `https://` address.
- The "Safest" security level turns JavaScript off, so the app can't run at that level. Not yet tested end to end in Tor Browser by the maintainers; reports welcome.

### A spare Android phone (or home computer) as the relay, with Cloudflare Tunnel

A tunnel lets a device at home act as a relay without opening ports: the device connects out to Cloudflare, and Cloudflare gives it a public `https://` address. You need a free Cloudflare account and a domain on Cloudflare, and Cloudflare sits between your users and the relay (it sees the same metadata a relay operator sees, never content).

1. On a phone, install **Termux** from [F-Droid](https://f-droid.org/packages/com.termux/), then `pkg update && pkg install cloudflared` and download the `linux-arm64` relay. On a computer, download the relay for it and [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).
2. Start the relay: `./lullwire-relay -forwarded-header CF-Connecting-IP -join-code <code>` (on a phone, run `termux-wake-lock` first).
3. In a second terminal:
   ```bash
   cloudflared tunnel login
   cloudflared tunnel create lullwire
   cloudflared tunnel route dns lullwire relay.example.com
   cloudflared tunnel run --url http://127.0.0.1:8080 lullwire
   ```
   Your relay is now at `https://relay.example.com/`.
4. Keep the device on, charging and online. On Android, turn off battery optimisation for Termux; Termux:Boot can start both commands after a reboot.

`cloudflared tunnel --url …` without an account also works for a quick test, but its random address changes on every restart, which breaks invites.

### IPFS (the app only)

IPFS can host the **app** (not the relay), so anyone can mirror it and its content address proves it hasn't been altered:

```bash
./scripts/publish-ipfs.sh https://relay.example.com/relay.php   # needs Kubo (ipfs)
```

Browser storage, which holds the keys, is tied to the exact web address, so use DNSLink for a stable address (`_dnslink.app.example.com TXT "dnslink=/ipfs/<cid>"`, opened at `https://app-example-com.ipns.dweb.link/`). Path-style gateway URLs (`…/ipfs/<cid>/`) share one origin with every IPFS site, so the app refuses to run there.

### The Android app

People you invite can use the web app in any browser, or install the **Android app** (not in any app store):

1. Download `lullwire-relay-<version>.apk` from the [releases page](https://github.com/altrudev/Lullwire-Relay/releases/latest). Official builds are signed by Valentyn Rukhaylo (ALTRU.dev) with the certificate
   `38:40:AF:64:FB:BB:D8:43:D6:A9:1F:7F:C0:F7:03:AF:AB:AD:32:4F:A0:8C:D4:24:A5:74:32:5E:00:CD:53:19`
   (check with `apksigner verify --print-certs`). Android only installs updates signed with the same certificate, so a tampered update can't replace the real app.
2. Open it on the phone and allow installing from that source when Android asks.
3. On the welcome screen, paste the invite link someone sent you (or share the link to the app), then create your profile. Without an invite, enter your relay's address (and join code, if it has one) under **Advanced**.

The app bundles the same code as the web app and connects only to the relays you use. It blocks screenshots, keeps everything encrypted with its key in the Android Keystore, and is excluded from cloud backups. With **Stay connected in the background** (Settings) it keeps one connection to your relay open while closed, so messages and calls arrive with a notification; no Google services or push servers are involved. There's no automatic update: install a new release over the old one.

**Building it yourself** (no Gradle; the plain Android SDK tools: JDK 17+, build-tools 34+, one platform 35+):

```bash
./android/build.sh            # signed release APK in android/out/, plus a .sha256 file
./android/build.sh --debug    # debug build: remote WebView inspector on, screenshots allowed
```

The first release build creates a signing key at `~/.lullwire-relay/release.jks` (or `LULLWIRE_KEYSTORE`; the password comes from `LULLWIRE_KEYPASS` or a prompt). **Back that key up and keep it offline:** Android only installs updates signed with the same key. Your own build installs as a separate app from the official one; if you distribute a modified build, give it its own name, icon and application id (see the [brand guide](../assets/brand/README.md)).
