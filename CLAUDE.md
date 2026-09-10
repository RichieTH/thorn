# Thorn

Security-hardened repo scanner CLI. Detects hardcoded secrets, committed `.env` files, and common misconfigurations. Built in parallel in Rust and Go to benchmark both implementations.

## Project Structure

```
thorn/
├── thorn-rs/       # Rust implementation (cargo install thorn)
├── thorn-go/       # Go implementation (go install)
├── fixtures/       # Shared dirty test repos for both implementations
├── bench/          # Benchmark + comparison scripts
└── .claude/        # Claude Code rules and memory
```

## Goals

- Single static binary, no runtime dependencies
- Cross-platform: Windows, Linux, macOS
- `thorn .` scans current directory recursively
- Security-hardened output by default
- `--json` flag for machine-readable output
- Monetized via Lemon Squeezy (free tier + paid license key for full ruleset)

## v0.1 Scope (DO NOT EXPAND UNTIL DONE)

1. Recursive directory scan
2. Hardcoded secrets detection (API keys, tokens, passwords)
3. Committed `.env` file detection
4. Common misconfig detection (Dockerfile runs as root, debug flags in configs)
5. Severity-leveled terminal output (CRITICAL / HIGH / MEDIUM / INFO)
6. `--json` flag

## Architecture Decisions

- Rust: use `walkdir`, `regex`, `clap`, `serde_json`, `colored`
- Go: use `filepath.Walk`, `regexp`, `cobra`, `encoding/json`
- Both implementations must produce identical JSON output schema
- Rule definitions live in code, not external files (for single-binary distribution)
- No network calls, no telemetry, no external dependencies at runtime

## JSON Output Schema

```json
{
  "version": "0.1.0",
  "scanned_at": "<ISO8601>",
  "target": "<path>",
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|INFO",
      "rule_id": "SEC001",
      "rule_name": "Hardcoded AWS Secret Key",
      "file": "relative/path/to/file.py",
      "line": 42,
      "match": "REDACTED"
    }
  ],
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "info": 0
  }
}
```

## Rule IDs

| ID     | Category   | Description                          | Severity |
|--------|------------|--------------------------------------|----------|
| SEC001 | Secrets    | AWS Access Key ID                    | CRITICAL |
| SEC002 | Secrets    | AWS Secret Access Key                | CRITICAL |
| SEC003 | Secrets    | Generic API key pattern              | HIGH     |
| SEC004 | Secrets    | Hardcoded password in code           | HIGH     |
| SEC005 | Secrets    | Private key / PEM block              | CRITICAL |
| SEC006 | Secrets    | GitHub/GitLab personal access token  | HIGH     |
| ENV001 | Dotenv     | .env file committed to repo          | HIGH     |
| ENV002 | Dotenv     | .env.production committed            | CRITICAL |
| CFG001 | Misconfig  | Dockerfile USER root                 | MEDIUM   |
| CFG002 | Misconfig  | Debug mode enabled in config         | MEDIUM   |
| CFG003 | Misconfig  | Hardcoded localhost/127.0.0.1        | INFO     |

## Coding Standards

- Rust: edition 2021, stable toolchain, `cargo clippy` clean, `cargo fmt` enforced
- Go: 1.22+, `gofmt` enforced, `go vet` clean
- Both: no `unwrap()` / `panic!()` in non-test code (Rust), handle all errors explicitly
- Inline comments only when intent isn't obvious
- Every rule must have a corresponding fixture file in `fixtures/`

## Testing Requirements

- Unit tests for every rule (positive + negative cases)
- Integration test: run scanner against `fixtures/` and assert expected findings
- Both implementations must pass the same fixture-based integration test suite
- Run tests before every commit

## Benchmarking

- `bench/compare.sh` runs both binaries against `fixtures/` and outputs timing
- Goal: document which is faster and by how much for the README

## Distribution Plan

- GitHub Releases: pre-built binaries for win/linux/mac (amd64 + arm64)
- `cargo install thorn-scan` (thorn is taken on crates.io)
- `go install github.com/RichieTH/thorn/thorn-go/cmd/thorn@latest`
- Homebrew tap: `brew install RichieTH/tap/thorn`
- Scoop bucket for Windows

## Monetization

- Free: SEC001-003, ENV001, CFG001 (enough to be useful)
- Paid ($29 one-time or $9/mo): full ruleset + JSON output + CI mode (exit code 1 on findings)
- License key validation is offline (hash check, no network call)
- Sold via Lemon Squeezy

**v0.2 implementation note**: the "CI mode (exit code 1 on findings)" gate is now
built — see `--fail-on-findings` in README's Usage section and
`thorn-rs/src/license.rs` / `thorn-go/internal/license/license.go`. It gates
*only* that exit-code behavior, not JSON output or the rule set — both remain
free/unconditional as already shipped in v0.1. Full rule-tier gating is still
undecided/unbuilt.

License validation could not actually be a plain "hash check" as originally
written above: thorn's source is public, so any shared secret used for hashing
would be readable in the repo, letting anyone mint their own valid key. It's
implemented instead as offline Ed25519 signature verification — the public
verification key is safely embedded in the public source; the private signing
key (used to mint real keys) lives outside the repo entirely, along with a
key-generation script, in a location documented in `docs/development.md`.
Lemon Squeezy integration (actually selling/issuing keys) is still unbuilt — this
only covers verifying a key that already exists.

## Current Status

- [x] thorn-rs v0.1 implementation
- [x] thorn-go v0.1 implementation
- [x] Fixture files
- [x] Unit tests
- [x] Integration tests
- [x] Benchmark script
- [x] GitHub Actions CI (lint + test on push)
- [x] GitHub Release workflow (build binaries)
- [x] README with install instructions (demo gif still outstanding — needs an actual terminal recording, deferred; a static example-output block stands in for now)

### v0.2 (in progress)

- [x] Suppression: inline `thorn-ignore` comments + `.thornignore` file
- [x] SARIF output (`--sarif`)
- [x] License-gated `--fail-on-findings` (Ed25519 signature verification)
- [x] Dual-signed release `checksums.txt` (GPG + ML-DSA-65/Dilithium) and
      `thorn verify-release` — see docs/architecture.md. Code-signing the
      binaries themselves (Windows Trusted Signing, macOS notarization) is
      still on hold pending paid Azure/Apple developer accounts.
- [ ] Git history scanning — explicitly descoped from v0.2, needs its own round
      (shells out to system `git` or adds a git library in each language — either
      is a real departure from "single static binary, no runtime dependencies"
      and deserves dedicated planning, not a bolt-on)
