# Contributing to Lullwire Relay

Contributions to documentation, tests, interoperability and security hardening are welcome.

## Before opening a pull request

1. Review the project [scope and limitations](ABOUT.md) and [security policy](SECURITY.md).
2. Keep changes focused and describe the threat model, behavior or bug being addressed.
3. Keep the zero-dependency design: vanilla JavaScript and WebCrypto in the app, the Go standard library in the relay, plain Java in the Android shell, no build step for the web app.
4. Run `./tests/run.sh --go` (Go 1.22+, Node.js 20+, curl) and `./tests/run.sh` (PHP relay). For UI or call changes, add `--e2e` (Python Playwright and Chromium). For Android changes, run `SERIAL=<device> ./tests/android/run.sh` on an emulator (Android SDK, JDK 17+).
5. Include tests for regressions, malformed inputs, network failure and replay or authentication failure paths where relevant.
6. Do not add analytics, tracking or telemetry by default. Avoid committing credentials, recovery words, private keys or relay mailbox data.
7. Explain new dependencies and include their upstream license and attribution notices.

## Vulnerability reporting

Do **not** post exploit details or sensitive vulnerabilities in public issues or pull requests. Use GitHub's **Report a vulnerability** feature under the repository Security tab. See [SECURITY.md](SECURITY.md) for scope and reporting details.

## Licensing submissions

Before your first pull request can be merged, you need to agree to the [Contributor License Agreement](CLA.md) (CLA). The pull request template contains the one sentence to keep.

In short: **you keep the copyright** in your work and it stays available to everyone under AGPL-3.0-or-later, and you give the maintainer, Valentyn Rukhaylo (ALTRU.dev), a licence to also offer the project under other terms (for example a commercial licence), which is how the project can fund itself. Contributing for an employer? Ask for the organization version first.

Third-party code you include must be compatible with the project license and must retain its required notices.

New source files start with the project header:

```
Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
SPDX-License-Identifier: AGPL-3.0-or-later
```

If you add a substantial file of your own, you may add a line with your name below it. Please don't change existing copyright lines, the [NOTICE](NOTICE) file or the logo; forks that ship modified builds should use their own name and icon (see the [brand guide](assets/brand/README.md)).

## Maintainer review

A passing automated test suite alone does not establish cryptographic security. Changes to encryption, identity, relay authorization, recovery or device linking require adversarial review and careful interoperability testing before release.
