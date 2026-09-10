# Development

## Prerequisites

- Rust: stable toolchain, edition 2021, MSRV 1.75 (install via
  [rustup](https://rustup.rs))
- Go: 1.22+, no CGO (install from [go.dev](https://go.dev/dl/))
- Neither is installed by default on a fresh machine — if you're setting up from
  scratch, `rustup-init` / the Go installer are the paths of least resistance.
  On Windows specifically: installing via `winget` can silently stall on a UAC
  elevation prompt that never surfaces in a non-interactive shell — if an install
  hangs far longer than it should, check for an orphaned `msiexec`/installer
  process before assuming it's just slow.

## Build & test — Rust

```bash
cd thorn-rs
cargo build --release        # -> target/release/thorn(.exe)
cargo test                   # unit tests (in every rules/*.rs) + integration.rs
cargo clippy --all-targets -- -D warnings   # must be clean, including test code
cargo fmt -- --check         # must be clean (cargo fmt to fix)
```

`cargo test` runs two suites:
- Unit tests live in `#[cfg(test)] mod tests` blocks **inside** each rule file
  (e.g. `thorn-rs/src/rules/secrets.rs`), not in separate files.
- [`tests/integration.rs`](../thorn-rs/tests/integration.rs) builds the real
  `thorn` binary (via `env!("CARGO_BIN_EXE_thorn")`) and runs it against
  `../fixtures/` from the crate root — asserting `rule_id` + file per fixture,
  a well-formed JSON summary, `--min-severity` filtering, and a clean-directory
  case with zero findings. It does **not** assert exact line numbers (per
  [`.claude/rules/testing.md`](../.claude/rules/testing.md) — fragile).

## Build & test — Go

```bash
cd thorn-go
go build -o bin/thorn ./cmd/thorn
go test ./...
go vet ./...
gofmt -l .                   # must print nothing (gofmt -w . to fix)
```

`go test ./...` runs three packages' worth of tests:
- Table-driven unit tests alongside each rule file (`secrets_test.go`,
  `dotenv_test.go`, `misconfig_test.go`).
- [`internal/scanner/scanner_test.go`](../thorn-go/internal/scanner/scanner_test.go)
  — the integration test, calling `Scan()` directly (not shelling out to a built
  binary, unlike Rust's approach) against `../../../fixtures/`.
  **This relative path is not a typo** — `go test`'s working directory is the
  package's own directory (`internal/scanner/`), so three levels up reaches
  `thorn/`, unlike Cargo's crate-root-relative integration tests. Getting this
  wrong silently makes every fixture-expectation assertion fail with "found
  nothing," which looks like a scanner bug but isn't — check the path first.

## Benchmark / cross-implementation check

```bash
cd bench
RUNS=3 bash compare.sh       # RUNS defaults to 10; env override for quick checks
```

Requires both release binaries already built at `thorn-rs/target/release/thorn` and
`thorn-go/bin/thorn`. Reports binary size, median scan time, and — critically —
**fails with exit 1 if the two implementations don't agree on the finding count**
against `fixtures/`. This is also run in CI (see [ci-cd.md](./ci-cd.md)).

The script is invoked as `bash compare.sh`, not `./compare.sh`, in CI — a file
created/edited on Windows has no Unix executable bit for git to record (NTFS has no
such concept), so `./compare.sh` fails with `Permission denied` on a Linux runner
even though the file's own shebang is correct. If you edit this script on Windows,
either re-run `git update-index --chmod=+x bench/compare.sh` or just keep invoking
it via `bash compare.sh`.

## Coding standards (enforced by CI, not just convention)

- **Rust:** no `unwrap()`/`expect()`/`panic!()` outside `#[cfg(test)]` code. Every
  rule's regex compilation and the JSON serializer both follow the same pattern —
  fail soft (empty result / `"{}"`), never crash the process over a
  should-be-impossible error in a hardcoded, unit-tested literal.
- **Go:** handle all errors explicitly, no `_` discards, no log-and-continue in
  library code (`internal/`) — the one exception is the same "unit-tested literal
  regex, can't actually fail" case as Rust, applied consistently.
- Both: `cargo clippy -- -D warnings` / `go vet ./...` clean, formatter clean.
  Inline comments only when intent isn't obvious from the code itself.
- See [`.claude/rules/rust.md`](../.claude/rules/rust.md) and
  [`.claude/rules/go.md`](../.claude/rules/go.md) for the full, authoritative list.

## Adding a new rule

This has to happen in **both** languages, plus fixtures and docs. Checklist, using
a hypothetical `SEC007` as the example:

1. **Pick the ID.** Next unused number in its category (`SEC`/`ENV`/`CFG`) — check
   [rules-reference.md](./rules-reference.md) and CLAUDE.md's table for what's
   taken.
2. **Design the pattern** with Go's RE2 engine in mind from the start — no
   lookahead/lookbehind, no backreferences, since the same pattern string has to
   work unmodified in Go's `regexp` package. See
   [architecture.md](./architecture.md#one-real-behavioral-difference-line-splitting)
   for why this matters.
3. **Implement in Rust** — add a unit struct + `impl Rule` in the relevant file
   under `thorn-rs/src/rules/` (or a new file if it's a new category), register it
   in `rules::all()` in [`mod.rs`](../thorn-rs/src/rules/mod.rs).
4. **Implement in Go** — mirror it in `thorn-go/internal/rules/`, register it in
   `All()` in [`registry.go`](../thorn-go/internal/rules/registry.go).
5. **Add a fixture** under `fixtures/<category>/` with at least one true-positive
   line and one line that should **not** match (false-positive guard). Add the
   `# thorn test fixture: SEC007` comment header per
   [`.claude/rules/testing.md`](../.claude/rules/testing.md). **Use an obviously
   fake value** — see the SEC003 landmine note in
   [rules-reference.md](./rules-reference.md#sec003--generic-api-key-pattern)
   before picking a realistic-looking secret format; GitHub's push protection
   blocks on format alone, not plausibility.
6. **Add unit tests** in both languages — at minimum one positive match, one
   negative (rust.md / go.md requirement).
7. **Update both integration tests' expectation tables** —
   `thorn-rs/tests/integration.rs`'s `expected` array and
   `thorn-go/internal/scanner/scanner_test.go`'s `expected` map — with the new
   fixture file and rule ID.
8. **Run everything**: both test suites, both linters/formatters, then
   `bash bench/compare.sh` to confirm both implementations report the same total
   finding count against the now-updated `fixtures/`.
9. **Update docs**: this rule's entry in
   [rules-reference.md](./rules-reference.md), the rule table in CLAUDE.md, and the
   README's "What it detects" table if it's user-facing.

Skipping any of steps 3–8 is how the two implementations silently drift apart — the
whole point of `cross-implementation-check` in CI is to catch that before merge, but
it's much cheaper to just do the checklist than to debug a mismatch after the fact.

## Local git quirks worth knowing

- **Windows checkouts don't preserve the Unix executable bit.** See the
  `bench/compare.sh` note above — this already broke CI once.
- **GitHub push protection is format-based, not content-based.** A fixture value
  that *looks* like a real secret format (even one deliberately named "FAKE...")
  gets blocked identically to a real one — see
  [ci-cd.md](./ci-cd.md#gotcha-1-github-push-protection-is-format-only) for the
  full story and what actually resolves it.
