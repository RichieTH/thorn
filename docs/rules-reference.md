# Rules reference

Every rule below is implemented identically (same regex, same severity, same
matching logic) in both [`thorn-rs`](../thorn-rs/src/rules/) and
[`thorn-go`](../thorn-go/internal/rules/). Patterns are shown in Rust `regex` syntax;
the Go `regexp` (RE2) versions are byte-for-byte the same pattern string, since RE2
compatibility was a constraint from the start (see
[architecture.md](./architecture.md#go-thorn-go)).

Free vs. paid tier is documented here because it's in CLAUDE.md's monetization
section — **not implemented anywhere in the code today**. All 11 rules currently run
regardless of license.

| Rule | Category | Severity | Tier (documented, unbuilt) |
|------|----------|----------|------------------------------|
| SEC001 | Secrets | CRITICAL | Free |
| SEC002 | Secrets | CRITICAL | Paid |
| SEC003 | Secrets | HIGH | Paid |
| SEC004 | Secrets | HIGH | Paid |
| SEC005 | Secrets | CRITICAL | Paid |
| SEC006 | Secrets | HIGH | Paid |
| ENV001 | Dotenv | HIGH | Free |
| ENV002 | Dotenv | CRITICAL | Paid |
| CFG001 | Misconfig | MEDIUM | Free |
| CFG002 | Misconfig | MEDIUM | Paid |
| CFG003 | Misconfig | INFO | Paid |

---

## SEC001 — AWS Access Key ID

- **Severity:** CRITICAL
- **Matching:** line-regex, any file
- **Pattern:** `` \bAKIA[0-9A-Z]{16}\b ``
- **Fixture:** [`fixtures/secrets/aws_keys.py`](../fixtures/secrets/aws_keys.py)
- **What it catches:** the standard AWS access key ID prefix (`AKIA`) followed by 16
  uppercase-alphanumeric characters — the real format AWS uses.

## SEC002 — AWS Secret Access Key

- **Severity:** CRITICAL
- **Matching:** line-regex, any file
- **Pattern:** `` (?i)aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']? ``
- **Fixture:** [`fixtures/secrets/aws_keys.py`](../fixtures/secrets/aws_keys.py)
- **What it catches:** a variable literally named `aws_secret_access_key` (case-
  insensitive) assigned a 40-character base64-alphabet string — the real length of
  an AWS secret key. Requires the variable name; a bare 40-char string alone won't
  trigger this (that would be far too noisy).

## SEC003 — Generic API key pattern

- **Severity:** HIGH
- **Matching:** line-regex, any file
- **Pattern:** `` (?i)(api[_-]?key\s*[:=]\s*["'][a-z0-9_\-]{16,}["'])|(\bsk_live_[A-Za-z0-9]{16,}\b)|(\bsk-[A-Za-z0-9]{16,}\b)|(\bpk_live_[A-Za-z0-9]{16,}\b) ``
- **Fixture:** [`fixtures/secrets/api_keys.js`](../fixtures/secrets/api_keys.js)
- **What it catches:** four alternatives — (1) any `apiKey`/`api_key`/`api-key`
  assignment to a 16+ char token, (2) `sk_live_...` (Stripe-style secret keys),
  (3) `sk-...` (OpenAI-style keys), (4) `pk_live_...` (Stripe-style publishable
  keys).
- **⚠️ Known landmine — do not add a real Stripe-format test value.** A fixture or
  test string matching `sk_live_[A-Za-z0-9]{16,}` closely enough is treated as a
  real Stripe secret by **GitHub's push protection**, which blocks the push
  regardless of how obviously fake the content is (it's a format match, not an
  entropy/plausibility check — confirmed empirically, see
  [ci-cd.md](./ci-cd.md#gotcha-1-github-push-protection-is-format-only)). The
  `sk_live_`/`pk_live_` branches of this rule are currently **not covered by a
  literal-value unit test** for exactly this reason — coverage relies on the
  `sk-` branch instead. If you need to test the Stripe-specific branches, do it
  with a value that's short enough to fail your own regex's `{16,}` minimum in the
  test itself (i.e. test the *boundary*, not a plausible real key).

## SEC004 — Hardcoded password in code

- **Severity:** HIGH
- **Matching:** line-regex, any file
- **Pattern:** `` (?i)\b\w*pass(word)?\w*\s*=\s*['"]?[^\s'",]{4,} ``
- **Fixture:** [`fixtures/secrets/api_keys.js`](../fixtures/secrets/api_keys.js)
- **What it catches:** any word containing `pass` or `password` (case-insensitive,
  so `dbPassword`, `admin_password`, `PASS` all match) assigned a value of 4+
  non-whitespace/quote/comma characters. Deliberately loose — this is a HIGH not
  CRITICAL rule precisely because it's a heuristic prone to false positives on
  things like `passed_tests = 47`.

## SEC005 — Private key / PEM block

- **Severity:** CRITICAL
- **Matching:** line-regex, any file
- **Pattern:** `` -----BEGIN\s+[A-Z ]*PRIVATE KEY----- ``
- **Fixture:** [`fixtures/secrets/private_key.txt`](../fixtures/secrets/private_key.txt)
- **What it catches:** the PEM header line for any private key type (`RSA PRIVATE
  KEY`, `EC PRIVATE KEY`, `PRIVATE KEY`, etc.) — matches on the `BEGIN` line only,
  doesn't need the full block. Deliberately does **not** match `PUBLIC KEY` headers.

## SEC006 — GitHub/GitLab personal access token

- **Severity:** HIGH
- **Matching:** line-regex, any file
- **Pattern:** `` \bgh[pousr]_[A-Za-z0-9]{20,}\b|\bglpat-[A-Za-z0-9_-]{16,}\b ``
- **Fixture:** [`fixtures/secrets/github_token.yaml`](../fixtures/secrets/github_token.yaml)
- **What it catches:** GitHub's real PAT prefixes — `ghp_` (personal), `gho_`
  (OAuth), `ghu_` (user-to-server), `ghs_` (server-to-server), `ghr_` (refresh) —
  each followed by 20+ alphanumeric chars; and GitLab's `glpat-` prefix followed by
  16+ chars.

## ENV001 — `.env` file committed to repo

- **Severity:** HIGH
- **Matching:** filename only, content ignored
- **Fixture:** [`fixtures/dotenv/.env`](../fixtures/dotenv/.env)
- **What it catches:** any file whose basename is exactly `.env`. Existence alone is
  the finding — a `.env` file should never be in version control regardless of what
  it contains.
- **Note:** does not match `.env.local`, `.env.development`, or other `.env.*`
  variants — only the exact filename. This is a deliberate scope limit, not an
  oversight; extending it to variants is a reasonable small addition if ever needed.

## ENV002 — `.env.production` committed

- **Severity:** CRITICAL
- **Matching:** filename only, content ignored
- **Fixture:** [`fixtures/dotenv/.env.production`](../fixtures/dotenv/.env.production)
- **What it catches:** exactly `.env.production`. Ranked CRITICAL over ENV001's HIGH
  because production credentials are a strictly worse leak than
  local/dev ones — same detection shape, higher stakes.

## CFG001 — Dockerfile `USER root`

- **Severity:** MEDIUM
- **Matching:** two-pass, `Dockerfile*` files only
- **Fixture:** [`fixtures/misconfigs/Dockerfile`](../fixtures/misconfigs/Dockerfile)
- **What it catches:** two distinct cases, in priority order:
  1. An explicit `USER root` line (case-insensitive) — reported at that line,
     scan stops there.
  2. No `USER` directive anywhere in the file — reported at the last line, since a
     Dockerfile with no `USER` line runs as root **implicitly**. This is the one
     rule with real control flow (see
     [architecture.md](./architecture.md#the-scan_lines-pattern)).
- **Filename match:** any file whose basename **starts with** `Dockerfile` (so
  `Dockerfile`, `Dockerfile.dev`, `Dockerfile.prod` all qualify).

## CFG002 — Debug mode enabled

- **Severity:** MEDIUM
- **Matching:** line-regex, any file
- **Pattern:** `` (?i)\b(debug|flask_debug|debug_mode)\s*=\s*(true|1)\b ``
- **Fixture:** [`fixtures/misconfigs/settings.py`](../fixtures/misconfigs/settings.py)
- **What it catches:** `DEBUG=True`, `FLASK_DEBUG=1`, `debug_mode = true` (and case
  variants). Also fires on `.env` files containing a `DEBUG=true` line — this rule
  isn't restricted to config filenames, since debug flags can legitimately live in
  either.

## CFG003 — Hardcoded localhost/127.0.0.1

- **Severity:** INFO
- **Matching:** line-regex, any file
- **Pattern:** `` (?i)(127\.0\.0\.1|localhost) ``
- **Fixture:** [`fixtures/misconfigs/settings.py`](../fixtures/misconfigs/settings.py)
- **What it catches:** the literal strings `127.0.0.1` or `localhost` anywhere in a
  line. Lowest severity by design — this is informational (a hint something might
  be environment-specific), not a security finding.

---

## Adding a new rule

See [development.md](./development.md#adding-a-new-rule) for the full checklist —
in short: pick the next unused ID in its category, implement it identically in both
languages, add a fixture with both a true-positive and a false-positive line, add
unit tests for both, add it to both `all()`/`All()` registries, and add the ID to
CLAUDE.md's rule table and this file.
