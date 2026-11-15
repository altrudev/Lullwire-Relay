# safeaudit — check catalog

Each check encodes a security/privacy **design lesson**. Severity is a starting
point for triage, not a verdict. The automated checks find *smells and
absences*; the manual checks below them are the ones no scanner can verify.

> A clean run does **not** mean the app is secure. It means these specific
> smells were absent. Residual risk always remains — write it down (C7).

## Automated checks

| ID | Lesson | What it flags | Severity | Known false positives |
|----|--------|---------------|----------|-----------------------|
| C1 | Pin by digest — mutable tags are a supply-chain channel | `FROM`/`image:` without `@sha256:` | HIGH / MED | A compose `image:` that has a sibling `build:` is built locally — ignore. Digest-pinned-ARG `FROM ${VAR}` is resolved and passed. |
| C2 | Never weaken TLS; a security path forces verification | `InsecureSkipVerify`, `rejectUnauthorized:false`, `NODE_TLS_REJECT…=0`, `curl -k`, `--no-check-certificate`, `verify=False`; `sslmode=disable` (MED) | HIGH / MED | Full-line comments are excluded. A deliberate choice (e.g. a scanner hitting self-signed targets) is still flagged so a human signs off. |
| C3 | Secrets never enter git or an image layer | key/cert files, inlined PRIVATE KEY, tracked `.env`, hardcoded token patterns | HIGH | `.env.example`/`.sample` excluded. Use `gitleaks` for real coverage. |
| C4 | Least privilege + default-closed | Dockerfile without `USER`, compose without `no-new-privileges`, ports published to all interfaces, `0.0.0.0` binds | MED / LOW | Public services legitimately bind `0.0.0.0` — flag asks "is public intended?" |
| C5 | Dependency install is code execution | `npm ci/install` without `--ignore-scripts` in a build path | LOW | Dev-only scripts are fine; this matters most in images/CI. |
| C6 | Crown jewels must not sit in served content | `.env`/`.key`/`.pem` under `public/ static/ www/ assets/` | HIGH | — |
| C7 | Enumerate residual risk in writing | no `SECURITY.md` / threat-model doc | INFO | — |
| C8 | A fetched URL / exec'd command from config is an RCE channel | config/env value flowing into `exec`/`spawn`/`system` | LOW | Heuristic pointer only — see manual C8/C9 below. |

## Manual review — a scanner cannot verify these

- **C8 Configurable-surface → privilege.** For every setting, env var, and
  request field, ask: *if an attacker set this, what do they get?* URLs that get
  fetched, paths read/written, command names executed, redirect/webhook targets
  — these should rarely be user-writable, and never without the same
  authorization as a code deploy. (The ARTEX backdoor was one changed config
  line choosing which image to pull.)
- **C9 Download / update integrity.** Anything that becomes executable or
  trusted (updates, plugins, imported models/configs) must be integrity-checked
  **independently of the channel**: host allowlist, forced TLS on a dedicated
  client, size cap, and a checksum compared against a signed sums file. "It came
  over HTTPS" is not integrity. Re-validate the destination on **every** redirect
  hop.
- **C10 Centralized side-effect boundary.** Is there one choke point every
  dangerous action passes through (authorization + audit), or is the check
  copy-pasted across features where one will be forgotten?
- **C11 Data-sensitivity map.** Where do secrets, tokens, PII, and captured
  evidence pool? Are the crown jewels on a separate store/volume, out of any
  directory that is served or backed up publicly? For each component: "if this
  is popped, what spills?"
- **C12 Audit-log robustness.** Audit writes must survive hostile input (invalid
  UTF-8, NUL bytes, huge fields) without silently dropping the record — a lost
  audit entry is a privacy/forensics failure.
- **C13 Secrets lifecycle.** Enter at runtime (not baked into images), live in
  memory or a `0600` file, never in logs or history. Dependencies pinned and
  lifecycle scripts controlled.

## The meta-rule

Layer the controls so each assumes the others failed, then ask: *if any single
control is bypassed, am I still okay?* If the answer needs one control to be
perfect, add another layer.
