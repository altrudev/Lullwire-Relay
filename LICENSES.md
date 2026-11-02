# Licensing and third-party notices

## Lullwire Relay original materials

Copyright © 2026 Valentyn Rukhaylo (ALTRU.dev). Created, designed and maintained by Valentyn (Val) Rukhaylo. See [NOTICE](NOTICE).

Unless a file specifically identifies a separate license, original source code and documentation written for Lullwire Relay are licensed under the **GNU Affero General Public License, version 3 or any later version** (SPDX identifier: `AGPL-3.0-or-later`). The authoritative full license text appears in [LICENSE](LICENSE).

This is **free software**, including for commercial purposes, subject to the license conditions. You may use, study, copy and modify it under the AGPL terms. Source distribution and providing access to modified hosted software can trigger obligations under the license, including the network-use provisions of section 13. Read the complete license before distributing or operating a modified service. This summary is informational and is not a substitute for the license text or legal advice.

The AGPL license does **not** give permission to use the "Lullwire Relay" or "ALTRU.dev" names or the Lullwire Relay logo as trademarks or endorsements (AGPL section 7(e)). Modified versions that you distribute or host need their own name and logo; see the [brand guide](assets/brand/README.md). No alternative proprietary license is granted through this repository; for a commercial license (to build on Lullwire Relay without the AGPL's obligations), contact the maintainer through https://altru.dev.

## Brand assets

The logo and promotional images in `assets/brand/` (and the app icons made from them in `web/` and `android/res/`) are © 2026 Valentyn Rukhaylo (ALTRU.dev). They ship with the source so the official app looks right, and may be used unmodified to refer to the project, as described in the [brand guide](assets/brand/README.md).

## Bundled third-party material

The project includes third-party assets under their original license terms, **not** relicensed as Lullwire Relay original code.

| Local files | Upstream origin | License | Preserved notice |
|---|---|---|---|
| `web/vendor/qrcode.js` | [qrcode-generator by Kazuhiko Arase](https://github.com/kazuhikoarase/qrcode-generator) | MIT | [LICENSE-qrcode-generator.txt](web/vendor/LICENSE-qrcode-generator.txt) and the source header |
| `web/vendor/jsQR.js` | [jsQR](https://github.com/cozmo/jsQR) | Apache License 2.0 | [LICENSE-jsQR.txt](web/vendor/LICENSE-jsQR.txt) |
| `web/vendor/words.js` | BIP39 English wordlist sourced from [@scure/bip39](https://github.com/paulmillr/scure-bip39) | MIT | [LICENSE-bip39-wordlist.txt](web/vendor/LICENSE-bip39-wordlist.txt) |

The Go relay binary (`cmd/lullwire-relay`) and the Android APK both embed the web app, including these files and their notice files, so sharing either one redistributes them too. The relay itself uses only the Go standard library (BSD-3-Clause, © The Go Authors), which is compiled into the binary. The Android app uses no third-party libraries; it is built against the Android SDK, whose platform classes are provided by the phone and are not bundled.

When redistributing the code or a binary, keep the relevant license text and copyright notices. These notices cover the identified bundled material and do not imply endorsement by its upstream authors.

## Warranty disclaimer

Lullwire Relay comes **WITHOUT ANY WARRANTY**, to the extent allowed by applicable law; see sections 15–17 of [LICENSE](LICENSE). The software is experimental, has not undergone an independent professional security audit, and should not be relied on for high-risk communications.

## Copyright and provenance

The copyright and creator credit above apply to the original Lullwire Relay code, documentation and brand assets, not to the works of third-party authors. Outside contributors keep the copyright in their own submissions and license them to the maintainer under the [Contributor License Agreement](CLA.md), which keeps them available under AGPL-3.0-or-later and also allows the maintainer to offer the project under additional terms, such as a commercial licence. Their authorship is recorded in the git history.
