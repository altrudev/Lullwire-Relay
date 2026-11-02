# Releasing Lullwire Relay

Everything runs on your own machine; there is no CI. Three keys sign a release, and all of them stay offline and backed up:

| Key | File | Signs |
|---|---|---|
| Web release key (ECDSA P-256) | `~/.lullwire-relay/web-signing.pem` | `web/release.json`, which installed web apps check before switching to new code |
| Android signing key | `~/.lullwire-relay/release.jks` (or the Hush Relay key `~/.hush-relay/release.jks`, which keeps the same certificate fingerprint) | the APK |
| Your git identity | | commits and tags |

## Once: the web release key

```bash
go run ./cmd/lullwire-release keygen
git add web/sw.js && git commit -m "Pin the web release key"
```

`keygen` makes the key (it never replaces an existing one) and pins its public half in `web/sw.js` (`const RELEASE_KEY = '…'`). Publish the fingerprint it prints (also shown in the app under Settings → App code) in the README and on the release page. Losing this key means installed web apps can't take updates until people reinstall from a fresh visit; leaking it lets someone sign code for those apps.

Until a key is pinned, builds are "unsigned" and the service worker keeps the old network-first behaviour.

## Each release

1. Set the version in `cmd/lullwire-relay/main.go` (`var version`), `android/AndroidManifest.xml` (`versionCode` + 1 and `versionName`), the footer in `web/index.html` (`appVer`) and `CHANGELOG.md`.
2. Run the tests: `./tests/run.sh --go --e2e`, `./tests/run.sh --e2e` (PHP) and, with an emulator or phone, `SERIAL=… ./tests/android/run.sh`.
3. Build the APK: `./android/build.sh`, then copy `android/out/lullwire-relay-<version>.apk` into `dist/`.
4. Build the relays: `./scripts/build-release.sh`. It signs the web app first (`web/release.json`, checked with `lullwire-release verify`), so every binary embeds a signed copy, then writes `dist/SHA256SUMS`.
5. Commit `web/release.json` with the release, tag it, and upload `dist/` to the GitHub release with the APK certificate fingerprint and the web release key fingerprint.
6. Optional IPFS copy: `./scripts/publish-ipfs.sh https://your-relay/…/relay` signs its own copy (its `config.js` differs) before adding it.

Copies of the app served from a folder (`-web`, cPanel) must include the matching `release.json`; any edited file (including `config.js`) needs `go run ./cmd/lullwire-release sign <version> -dir <folder>` again, or installed apps will refuse it as an update.
