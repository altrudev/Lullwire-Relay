#!/usr/bin/env bash
# safeaudit — design-level self-audit for apps you ship.
#
# It encodes security/privacy *design* lessons as checks, and orchestrates
# mature scanners (gitleaks, trivy, semgrep, hadolint) when they're installed.
#
# It finds SMELLS and ABSENCES, not proof. A clean run does not mean "secure."
# Read CHECKS.md for the manual-review items no scanner can verify.
#
# Usage:
#   ./safeaudit.sh [PATH]        full audit (default: .)
#   ./safeaudit.sh --fast [PATH] pre-commit subset (secrets + TLS-off only)
#   Exit code = number of HIGH findings (0 = none). Wire CI to fail on nonzero.

set -u

ROOT="."
FAST=0
for a in "$@"; do
  case "$a" in
    --fast) FAST=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) ROOT="$a" ;;
  esac
done
[ -d "$ROOT" ] || { echo "no such directory: $ROOT" >&2; exit 2; }

# Directories we never scan (noise + third-party code).
PRUNE='-path */.git -o -path */node_modules -o -path */vendor -o -path */dist -o -path */build -o -path */.next -o -path */target'
# Per-repo excludes: one glob per line in .safeauditignore (blank/# ignored).
# Use it for data/evidence/generated dirs that aren't code (e.g. queue/, *.json
# evidence) — keep it to non-code, never to hide a real source directory.
if [ -f "$ROOT/.safeauditignore" ]; then
  while IFS= read -r g; do
    case "$g" in ''|\#*) continue ;; esac
    PRUNE="$PRUNE -o -path */${g#/} -o -path */${g#/}/*"
  done < "$ROOT/.safeauditignore"
fi

HIGH=0; MED=0; LOW=0; INFO=0
red=$'\033[31m'; yel=$'\033[33m'; blu=$'\033[36m'; gry=$'\033[90m'; rst=$'\033[0m'

finding() { # SEV  ID  TITLE  DETAIL
  case "$1" in
    HIGH) HIGH=$((HIGH+1)); c=$red ;;
    MED)  MED=$((MED+1));  c=$yel ;;
    LOW)  LOW=$((LOW+1));  c=$blu ;;
    *)    INFO=$((INFO+1)); c=$gry ;;
  esac
  printf '%s[%s]%s %s — %s\n' "$c" "$1" "$rst" "$2" "$3"
  [ -n "${4:-}" ] && printf '      %s%s%s\n' "$gry" "$4" "$rst"
}

# grep helper: recursive, pruned, filename:line, quiet-safe.
scan() { # PATTERN  [extra grep flags]
  find "$ROOT" \( $PRUNE \) -prune -o -type f -print 2>/dev/null \
    | xargs -r grep -nEI ${2:-} -- "$1" 2>/dev/null
}
hits() { scan "$1" "${2:-}" | head -20; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "safeaudit — $ROOT  ($( [ $FAST = 1 ] && echo fast || echo full ))"
echo "------------------------------------------------------------"

# ---- C2  TLS verification disabled (always on, incl. fast) -----------------
# Lesson: never weaken cert validation; a security path must force TLS.
# nocmt drops full-line comments (path:line: //|#|*) so a comment that merely
# *mentions* the smell isn't flagged.
nocmt='^[^:]*:[0-9]+:[[:space:]]*(//|#|\*)'
m=$(scan 'InsecureSkipVerify[[:space:]]*[:=][[:space:]]*true|NODE_TLS_REJECT_UNAUTHORIZED[[:space:]]*[:=][[:space:]]*.?0|rejectUnauthorized[[:space:]]*:[[:space:]]*false|verify[[:space:]]*=[[:space:]]*False|CURLOPT_SSL_VERIFY(PEER|HOST)[[:space:]]*,[[:space:]]*(0|false)|curl\b[^|]*[[:space:]]-k\b|--no-check-certificate' | grep -vE "$nocmt")
[ -n "$m" ] && finding HIGH C2 "TLS/cert verification appears disabled" "$(echo "$m" | head -8) — confirm each is intentional, never accidental"
db=$(scan 'sslmode=disable' | grep -vE "$nocmt")
[ -n "$db" ] && finding MED C2 "DB TLS off (sslmode=disable)" "$(echo "$db" | head -4) — fine on a private network, risky over public"

# ---- C3  committed secrets (smell) (always on, incl. fast) -----------------
# Lesson: secrets never land in git history or an image layer.
# Only PRIVATE key material is a finding. A *public* key / cert is safe to commit
# (e.g. pinned trust anchors), so skip public-named files and files whose content
# is a public key only.
kp=""
while IFS= read -r file; do
  case "$file" in *public*|*pub.pem|*.crt|*.cer) continue ;; esac
  if printf '%s' "$file" | grep -qiE '\.(key|p12|pfx)$|id_rsa|private|secret' || grep -q 'PRIVATE KEY' "$file" 2>/dev/null; then
    kp="$kp$file"$'\n'
  fi
done < <(find "$ROOT" \( $PRUNE \) -prune -o -type f \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa' -o -name '*.p12' -o -name '*.pfx' \) -print 2>/dev/null)
[ -n "$kp" ] && finding HIGH C3 "Private key/cert material in tree" "$(printf '%s' "$kp" | head -20)"
pk=$(hits 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY')
[ -n "$pk" ] && finding HIGH C3 "Inlined PRIVATE KEY block" "$(echo "$pk" | head -5)"
if have git && git -C "$ROOT" rev-parse >/dev/null 2>&1; then
  tracked=$(git -C "$ROOT" ls-files 2>/dev/null | grep -E '(^|/)\.env($|\.)' | grep -vE '\.(example|sample|template)$' | head -10)
  [ -n "$tracked" ] && finding HIGH C3 ".env file tracked in git" "$tracked"
fi
tok=$(hits '(AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{30,}|sk-[0-9A-Za-z]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})')
[ -n "$tok" ] && finding HIGH C3 "Hardcoded API token pattern" "$(echo "$tok" | head -5)"

if [ "$FAST" = 1 ]; then
  echo "------------------------------------------------------------"
  echo "fast: HIGH=$HIGH  (run full audit before shipping)"
  exit "$HIGH"
fi

# ---- C1  unpinned base images / floating deps -----------------------------
# Lesson: pin by digest; the ARTEX backdoor rode in on a mutable tag.
df=$(find "$ROOT" \( $PRUNE \) -prune -o -type f \( -iname 'Dockerfile*' \) -print 2>/dev/null)
for f in $df; do
  # A FROM that references a variable (${IMG}) counts as pinned if the file
  # pins any ARG by digest — the common digest-pinned-ARG pattern.
  argpin=0
  grep -qE 'ARG[[:space:]]+[A-Za-z_]+=[^[:space:]]*@sha256:[0-9a-f]{64}' "$f" && argpin=1
  bad=""
  while IFS= read -r line; do
    ln=${line%%:*}; txt=${line#*:}
    img=$(printf '%s' "$txt" | sed -E 's/^[[:space:]]*FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?//I; s/[[:space:]]+AS[[:space:]]+[A-Za-z0-9_-]+[[:space:]]*$//I')
    case "$img" in
      scratch) continue ;;
      *@sha256:*) continue ;;
      *'$'*) [ "$argpin" = 1 ] && continue ;;
    esac
    bad="$bad$ln: FROM $img"$'\n'
  done < <(grep -nE '^[[:space:]]*FROM[[:space:]]' "$f")
  [ -n "$bad" ] && finding HIGH C1 "Base image not digest-pinned ($f)" "$(printf '%s' "$bad" | head -6)"
done
cf=$(find "$ROOT" \( $PRUNE \) -prune -o -type f \( -iname 'docker-compose*.y*ml' -o -iname 'compose*.y*ml' \) -print 2>/dev/null)
for f in $cf; do
  bad=$(grep -nE '^\s*image:\s*' "$f" | grep -vE '@sha256:[0-9a-f]{64}')
  [ -n "$bad" ] && finding MED C1 "Compose image not digest-pinned ($f)" "$(echo "$bad" | head -6)"
done

# ---- C4  container privilege & exposure ------------------------------------
# Lesson: least privilege; default-closed; bind to loopback.
for f in $df; do
  grep -qiE '^\s*USER\s+' "$f" || finding MED C4 "Dockerfile has no USER (runs as root) ($f)" "add a non-root USER, or document root as a named residual risk"
done
for f in $cf; do
  grep -qE 'no-new-privileges' "$f" || finding MED C4 "Compose missing no-new-privileges ($f)" ""
  pub=$(grep -nE '^\s*-\s*"?[0-9]' "$f" | grep -vE '127\.0\.0\.1|localhost')
  [ -n "$pub" ] && finding MED C4 "Port published to all interfaces ($f)" "$(echo "$pub" | head -6) — prefer 127.0.0.1: unless public is intended"
done
bind=$(hits '0\.0\.0\.0')
[ -n "$bind" ] && finding LOW C4 "Service binds 0.0.0.0 (review: is public intended?)" "$(echo "$bind" | head -5)"

# ---- C5  dependency install runs lifecycle scripts -------------------------
# Lesson: dependency install is code execution on your build machine.
ins=$(scan 'npm (ci|install)\b' | grep -vE 'ignore-scripts' | grep -iE 'dockerfile|\.ya?ml:|\.sh:')
[ -n "$ins" ] && finding LOW C5 "npm install without --ignore-scripts in build path" "$(echo "$ins" | head -6)"

# ---- C6  secrets commingled with served/static content ---------------------
# Lesson: crown jewels must not sit in a directory something else serves.
srv=$(find "$ROOT" \( $PRUNE \) -prune -o -type f \( -name '.env*' -o -name '*.key' -o -name '*.pem' \) \
       \( -path '*/public/*' -o -path '*/static/*' -o -path '*/www/*' -o -path '*/assets/*' \) -print 2>/dev/null | grep -vE '\.(example|sample)$' | head -10)
[ -n "$srv" ] && finding HIGH C6 "Secret inside a served/static directory" "$srv"

# ---- C8  configurable-surface -> privilege (heuristic pointer) -------------
# Lesson: a fetched URL / exec'd command from config is an RCE channel.
cfg=$(scan '(exec|spawn|system|popen|child_process|os\.system|subprocess)\b' | grep -iE 'env|config|getenv|process\.env|os\.environ' | head -8)
[ -n "$cfg" ] && finding LOW C8 "Config/env value flows into exec — review authorization" "$(echo "$cfg" | head -6) — see CHECKS.md C8/C9"

# ---- C7  design docs exist (INFO) ------------------------------------------
# Lesson: enumerate residual risk in writing; centralize the audit boundary.
doc=0
for p in SECURITY.md SECURITY SECURITY.rst THREATMODEL.md THREAT_MODEL.md docs/security.md .github/SECURITY.md; do
  [ -e "$ROOT/$p" ] && doc=1
done
find "$ROOT" -maxdepth 2 \( -iname 'security*.md' -o -iname 'security-model*' -o -iname '*threat*model*' \) 2>/dev/null | grep -q . && doc=1
[ "$doc" = 0 ] && finding INFO C7 "No SECURITY.md / threat-model doc found" "residual risk should be written down, not implied (CHECKS.md C7)"

# ---- Orchestrate mature scanners if present --------------------------------
echo "------------------------------------------------------------"
echo "external scanners:"
for t in gitleaks trivy grype semgrep hadolint; do
  if have "$t"; then echo "  ${blu}present${rst} $t — run it (see README)"; else echo "  ${gry}absent${rst} $t — install for deeper coverage"; fi
done

echo "------------------------------------------------------------"
printf 'summary  %sHIGH=%d%s  %sMED=%d%s  %sLOW=%d%s  INFO=%d\n' "$red" "$HIGH" "$rst" "$yel" "$MED" "$rst" "$blu" "$LOW" "$rst" "$INFO"
echo "reminder: this checks design smells, not correctness. CHECKS.md has the manual review."
exit "$HIGH"
