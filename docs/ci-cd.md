# CI/CD

Two workflows: [`ci.yml`](../.github/workflows/ci.yml) (every push/PR) and
[`release.yml`](../.github/workflows/release.yml) (on `v*` tags). Both were built,
broken, and fixed for real during this project's setup — the gotchas below aren't
hypothetical, they're what actually happened.

## `ci.yml` — three jobs, every push and PR

1. **`thorn-rs`** — `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D
   warnings`, `cargo test --locked`, `cargo build --release --locked`. Uploads the
   release binary as an artifact.
2. **`thorn-go`** — `gofmt -l .` (fails if non-empty), `go vet ./...`, `go test
   ./...`, `go build`. Uploads the binary.
3. **`cross-implementation-check`** — depends on both jobs above. Downloads both
   binaries, `chmod +x` them (see gotcha #2), runs `bash bench/compare.sh` with
   `RUNS=3` (faster than the default 10, since this only needs to confirm agreement,
   not produce a real benchmark). **This is the enforcement mechanism for
   `testing.md`'s "finding counts differing between implementations is a CI
   failure" rule** — it runs the actual built binaries against `fixtures/`, not
   just each language's own test suite in isolation.

Uses `--locked` on every cargo command — CI fails loudly if `Cargo.lock` drifts from
`Cargo.toml` instead of silently re-resolving dependencies to something that was
never actually tested.

Caching: `Swatinem/rust-cache` for Rust (workspace-aware, points at `thorn-rs ->
target`), `actions/setup-go`'s built-in cache for Go. Cache hits roughly halve job
time (observed: Rust 1m4s → 37s, Go 29s → 19s on a same-dependencies re-run).

## `release.yml` — 13 jobs, on `v*` tag push

- **`build-rust`**: 6-way matrix (linux/mac/windows × amd64/arm64), each producing
  a `.tar.gz` (unix) or `.zip` (windows) archive containing the `thorn` binary.
  `Swatinem/rust-cache` is keyed explicitly by `matrix.target` here — without that,
  6 differently-cross-compiled builds sharing one cache key would fight each other.
- **`build-go`**: 6-way matrix, same platform set, `CGO_ENABLED=0` for static
  binaries, built with `-ldflags="-s -w"` to strip debug info.
- **`publish`**: downloads all 12 artifacts, publishes them to a GitHub Release via
  `softprops/action-gh-release`, with auto-generated release notes.

### Cross-compilation notes (unverified beyond "it ran successfully once")

- **`aarch64-unknown-linux-gnu`**: needs `gcc-aarch64-linux-gnu` installed via apt
  and `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER` set — Rust can't link an
  arm64 binary with the default x86_64 linker.
- **`aarch64-pc-windows-msvc`**: builds from a `windows-latest` (x86_64) runner with
  just `rustup target add` — no extra linker config. This works because the MSVC
  toolchain on GitHub's Windows runner images includes arm64 target support
  out of the box.
- **`x86_64-apple-darwin`** from `macos-latest` (which is an Apple Silicon/arm64
  runner): cross-compiles fine via the system's universal Xcode clang, no extra
  setup needed.
- **Go's 6 targets** are all built from a single `ubuntu-latest` runner via
  `GOOS`/`GOARCH` env vars — trivial, since Go's toolchain cross-compiles natively
  and nothing here uses cgo.

These patterns match what other real-world Rust/Go CLI release workflows do, and
the actual v0.1.0 tag build succeeded across all 13 jobs — but if a *future* target
combination breaks, cross-compilation toolchain quirks are the first place to look.

## Making a release

```bash
git tag -a v0.1.0 -m "..."
git push origin v0.1.0
```

Any tag matching `v*` triggers `release.yml`. Verify afterward — don't just trust
the green checkmarks:

```bash
gh release view v0.1.0                          # lists all 12 expected assets
gh release download v0.1.0 --pattern "thorn-rs-x86_64-pc-windows-msvc.zip"
# unzip and actually run it against fixtures/ — confirm version + finding count
```

## Gotcha #1: GitHub push protection is format-only

A test fixture string matching Stripe's real secret-key **format**
(`sk_live_[A-Za-z0-9]{16,}`) gets blocked by GitHub's push protection, even when the
value is deliberately, obviously fake (`sk_live_FAKEFAKEFAKE...`). This was tested
directly: renaming the fake value's *content* did not help — the block persisted
identically, down to reusing the same internal "unblock" fingerprint ID regardless
of what the actual characters were. **The detector is pattern-based, not an
entropy/plausibility check.**

What doesn't work: making the fake value "look more obviously fake." What does
work: either (a) a repo admin visiting the `unblock-secret` URL GitHub provides and
choosing a reason like "used in tests," or (b) not committing a value that matches
the real format at all. This project chose (b) — see the SEC003 landmine note in
[rules-reference.md](./rules-reference.md#sec003--generic-api-key-pattern) — since
requesting a standing security exception on every future fixture felt like the
wrong default, and it was a cheap trade against slightly narrower test coverage for
one specific regex branch.

If you hit this on a *different* rule's fixture in the future, this is the tradeoff
to make consciously, not a bug to "fix" by regenerating a different-looking fake
value — that was tried, and it doesn't work.

## Gotcha #2: Windows checkouts lose the executable bit

[`bench/compare.sh`](../bench/compare.sh) was originally invoked as `./compare.sh`
in CI. It failed with `Permission denied` on the Linux runner — because the file
was authored/edited on Windows, where NTFS has no concept of a Unix executable bit
for git to record. The file was committed as mode `100644` instead of `100755`.

Fixed two ways (belt-and-suspenders): the git file mode was corrected
(`git update-index --chmod=+x bench/compare.sh`) **and** CI invokes it as `bash
compare.sh` rather than relying on the exec bit at all. If you add a new `.sh`
script to this repo and you're on Windows, do the same — check `git ls-files -s
<script>` shows `100755`, not `100644`.

## Gotcha #3: `setup-go`'s default cache lookup assumes a root-level `go.sum`

Both Go modules in this repo live under `thorn-go/`, not the repo root. Without
`cache-dependency-path: thorn-go/go.sum` explicitly set on the `actions/setup-go`
step, every CI run logged `Restore cache failed: Dependencies file is not found` —
harmless (caching just silently didn't happen), but wasteful. Easy to miss because
it's a warning annotation, not a failure.

## Action version policy

All actions are pinned to specific major versions (`actions/checkout@v7`, not
`@v4` or `@main`). When bumping, check the target repo's release notes for
breaking changes before just bumping the number — this project's `download-
artifact` v4→v8 bump was verified safe only because this repo uses `name`-based
artifact lookups, not the `artifact-ids` path that had an actual breaking change in
v5. `dtolnay/rust-toolchain@stable` is the one exception — it doesn't use semver
tags, `stable` is its intended floating reference.
