# thorn

[![CI](https://github.com/RichieTH/thorn/actions/workflows/ci.yml/badge.svg)](https://github.com/RichieTH/thorn/actions/workflows/ci.yml)

> Security scanner that catches what you missed before it ships.

`thorn` scans your repo for hardcoded secrets, committed `.env` files, and common misconfigurations. One command, zero config, zero network calls.

```bash
thorn .
```

Built in parallel in Rust (`thorn-rs`) and Go (`thorn-go`) to benchmark both implementations.

---

## Status

✅ **v0.1 released** — [download prebuilt binaries](https://github.com/RichieTH/thorn/releases/tag/v0.1.0) for win/linux/mac (amd64 + arm64), or `go install` below. Both implementations pass a shared fixture-based test suite and agree on every finding. Not yet published to crates.io or Homebrew.

---

## Install

### Direct binary
Download the archive for your platform from [GitHub Releases](https://github.com/RichieTH/thorn/releases/latest) — both `thorn-rs-*` and `thorn-go-*` builds are published for win/linux/mac (amd64 + arm64) on every tagged release, via the [release workflow](.github/workflows/release.yml).

### Go
```bash
go install github.com/RichieTH/thorn/thorn-go/cmd/thorn@latest
```

### Build from source
```bash
git clone https://github.com/RichieTH/thorn.git
cd thorn/thorn-rs && cargo build --release   # -> target/release/thorn
# or
cd thorn/thorn-go && go build -o bin/thorn ./cmd/thorn
```

### Rust (crates.io) — not yet published
```bash
cargo install thorn-scan   # coming soon; "thorn" was already taken
```

### Homebrew — not yet set up
```bash
brew install RichieTH/tap/thorn   # coming soon
```

---

## Usage

```bash
# Scan current directory
thorn .

# Scan a specific path
thorn /path/to/repo

# JSON output (for CI pipelines)
thorn --json .

# SARIF output (for GitHub code scanning -- upload with github/codeql-action/upload-sarif)
thorn --sarif . > results.sarif

# Specific severity threshold
thorn --min-severity HIGH .

# Fail the build on findings (paid feature -- requires a license key)
thorn --fail-on-findings --license-key <KEY> .
# or: THORN_LICENSE_KEY=<KEY> thorn --fail-on-findings .
```

### Suppressing findings

No flag needed -- both mechanisms are always honored:

- **Inline**: add `# thorn-ignore` (or the language's comment syntax) anywhere on
  the offending line to suppress every finding on it, or `# thorn-ignore:SEC001`
  to suppress only that rule.
- **`.thornignore`**: a gitignore-style file at the scan root. One pattern per
  line (`#` comments, blank lines skipped) -- a matching file or directory is
  skipped entirely, no rule ever sees its content.

---

## Example

Real output from `thorn ../fixtures` against this repo's own test fixtures (colors don't render in Markdown, but severities are color-coded in a real terminal — red/magenta/yellow/cyan for CRITICAL/HIGH/MEDIUM/INFO):

```
$ thorn ../fixtures
Scanning ../fixtures

[CRITICAL] .env.production committed — ../fixtures/dotenv/.env.production:1 (ENV002)
[CRITICAL] Hardcoded AWS Secret Key — ../fixtures/secrets/aws_keys.py:7 (SEC001)
[CRITICAL] AWS Secret Access Key — ../fixtures/secrets/aws_keys.py:8 (SEC002)
[CRITICAL] Private key / PEM block — ../fixtures/secrets/private_key.txt:4 (SEC005)
[HIGH] .env file committed to repo — ../fixtures/dotenv/.env:1 (ENV001)
[HIGH] Generic API key pattern — ../fixtures/dotenv/.env.production:6 (SEC003)
[HIGH] Generic API key pattern — ../fixtures/secrets/api_keys.js:5 (SEC003)
[HIGH] Hardcoded password in code — ../fixtures/secrets/api_keys.js:8 (SEC004)
[HIGH] Hardcoded password in code — ../fixtures/secrets/api_keys.js:9 (SEC004)
[HIGH] GitHub/GitLab personal access token — ../fixtures/secrets/github_token.yaml:5 (SEC006)
[HIGH] GitHub/GitLab personal access token — ../fixtures/secrets/github_token.yaml:6 (SEC006)
[MEDIUM] Debug mode enabled in config — ../fixtures/dotenv/.env:6 (CFG002)
[MEDIUM] Dockerfile USER root — ../fixtures/misconfigs/Dockerfile:6 (CFG001)
[MEDIUM] Debug mode enabled in config — ../fixtures/misconfigs/settings.py:4 (CFG002)
[MEDIUM] Debug mode enabled in config — ../fixtures/misconfigs/settings.py:5 (CFG002)
[MEDIUM] Debug mode enabled in config — ../fixtures/misconfigs/settings.py:6 (CFG002)
[INFO] Hardcoded localhost/127.0.0.1 — ../fixtures/dotenv/.env:4 (CFG003)
[INFO] Hardcoded localhost/127.0.0.1 — ../fixtures/misconfigs/settings.py:8 (CFG003)
[INFO] Hardcoded localhost/127.0.0.1 — ../fixtures/misconfigs/settings.py:9 (CFG003)
[INFO] Hardcoded localhost/127.0.0.1 — ../fixtures/misconfigs/settings.py:10 (CFG003)

20 findings: 4 critical, 7 high, 5 medium, 4 info
```

Note the `match` field is never shown — output is security-hardened by default, so findings never echo the actual secret text, even in `--json` mode.

*(A proper animated terminal-recording GIF/asciinema demo is still on the TODO list — this static example is a stand-in for now.)*

---

## What it detects

| Rule   | Description                         | Severity |
|--------|-------------------------------------|----------|
| SEC001 | AWS Access Key ID                   | CRITICAL |
| SEC002 | AWS Secret Access Key               | CRITICAL |
| SEC003 | Generic API key pattern             | HIGH     |
| SEC004 | Hardcoded password                  | HIGH     |
| SEC005 | Private key / PEM block             | CRITICAL |
| SEC006 | GitHub/GitLab personal access token | HIGH     |
| ENV001 | `.env` file committed               | HIGH     |
| ENV002 | `.env.production` committed         | CRITICAL |
| CFG001 | Dockerfile running as root          | MEDIUM   |
| CFG002 | Debug mode enabled                  | MEDIUM   |
| CFG003 | Hardcoded localhost                 | INFO     |

---

## Development

See [CLAUDE.md](./CLAUDE.md) for scope, schema, and coding standards, and
[docs/](./docs/) for the full context library — architecture, a complete rules
reference, a development guide (including how to add a new rule), CI/CD internals,
and current project status.

```bash
# Rust
cd thorn-rs && cargo build --release && cargo test

# Go
cd thorn-go && go build ./... && go test ./...

# Benchmark both
cd bench && ./compare.sh
```

---

## License

MIT
