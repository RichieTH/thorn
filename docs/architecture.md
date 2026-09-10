# Architecture

## The shape of the problem

`thorn <path>` needs to: walk a directory tree, run every detection rule against
every file's content, collect findings, and render them as colored terminal output
or JSON. Both implementations solve this with the same four-module split, because
that split maps directly onto the four things that change independently:

- **rules** — what counts as a finding (changes often: new rule, tweak a regex)
- **scanner** — how files get walked and handed to rules (changes rarely)
- **output** — how findings get presented (changes when adding a new format)
- **main / cmd** — CLI wiring (changes when adding a flag)

## Rust: `thorn-rs/`

```
thorn-rs/src/
├── main.rs           CLI entrypoint (clap), orchestration, sort/filter
├── rules/
│   ├── mod.rs         Rule trait, Severity, Finding, the `all()` registry
│   ├── secrets.rs      SEC001–006
│   ├── dotenv.rs        ENV001–002
│   └── misconfig.rs     CFG001–003
├── scanner/
│   ├── mod.rs         scan(root, rules) -> Vec<Finding>
│   └── walker.rs        WalkDir wrapper — file discovery + filtering
└── output/
    ├── json.rs         schema-exact JSON report
    └── terminal.rs       colored human-readable report
```

### The `Rule` trait

```rust
pub trait Rule {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding>;

    fn finding_at(&self, file: &str, line: usize) -> Finding { /* default impl */ }
}
```

Every rule is a zero-sized unit struct (`pub struct AwsAccessKeyId;`) implementing
this trait. `rules::all()` returns `Vec<Box<dyn Rule>>` — the registry is just a
literal list in [`rules/mod.rs`](../thorn-rs/src/rules/mod.rs). There is no dynamic
rule loading, no config file, no plugin system — this is deliberate
(CLAUDE.md: "Rule definitions live in code, not external files, for single-binary
distribution").

### `Severity`

```rust
pub enum Severity { Info, Medium, High, Critical }  // ascending order matters
```

Declaration order *is* the ordering — `derive(PartialOrd, Ord)` uses it directly, so
`Severity::Critical > Severity::High` falls out for free and `--min-severity`
filtering is just `findings.retain(|f| f.severity >= min)`. If you ever need a new
severity level, where you insert it in the enum is the whole design decision.

### `Finding`

```rust
pub struct Finding {
    pub severity: Severity,
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub file: String,
    pub line: usize,
    #[serde(rename = "match")]
    pub redacted_match: &'static str,   // ALWAYS "REDACTED" — see below
}
```

**`redacted_match` is never the actual matched text.** This isn't a placeholder to
fill in later — it's the whole point of "security-hardened output by default"
(CLAUDE.md goal #4). A secret scanner that prints the secrets it finds into CI logs
defeats itself. Every `Rule::scan` implementation constructs findings via the
trait's `finding_at()` default method, which hardcodes `"REDACTED"` — there is no
code path that threads the actual match text into a `Finding` at all. If you're
tempted to add one (e.g. "show me the last 4 chars for confirmation"), that's a
deliberate scope decision to raise with whoever owns the project, not a bug fix.

### Scanning a file: the `scan_lines` pattern

Most rules are line-based regex matches. [`secrets.rs`](../thorn-rs/src/rules/secrets.rs)
factors this into a shared helper:

```rust
fn scan_lines(pattern: &str, rule: &dyn Rule, file: &str, content: &str) -> Vec<Finding> {
    let Ok(pattern) = Regex::new(pattern) else { return Vec::new(); };
    content.lines().enumerate()
        .filter(|(_, line)| pattern.is_match(line))
        .map(|(idx, _)| rule.finding_at(file, idx + 1))
        .collect()
}
```

Note the regex is compiled **inside** `scan_lines`, per file, per rule — not cached
globally. This is a real inefficiency (11 rules × N files = up to 11 regex compiles
per file), traded deliberately for simplicity in v0.1. If scan performance on large
repos ever becomes a problem, this is the first place to look — precompiling regexes
once (e.g. via `std::sync::OnceLock`) is the natural fix. It hasn't been necessary at
v0.1 scale.

Also note: **if `Regex::new` fails, the rule silently returns no findings** rather
than panicking. This is not laziness — see the "no `unwrap()`/`expect()` outside
tests" rule in [`.claude/rules/rust.md`](../.claude/rules/rust.md). Since every
pattern is a hardcoded literal covered by a unit test, a compile failure here can
only mean a bug introduced in this exact commit, and the unit test for that rule
will catch it — so failing the whole scan process isn't warranted.

Not every rule fits the line-regex shape:
- **ENV001/ENV002** ([`dotenv.rs`](../thorn-rs/src/rules/dotenv.rs)) are pure
  filename matches — `content` is ignored entirely.
- **CFG001** ([`misconfig.rs`](../thorn-rs/src/rules/misconfig.rs)) needs two
  passes over the file: first look for an explicit `USER root` line (report and
  stop), then if no `USER` directive exists *at all*, report that too (a Dockerfile
  with no `USER` line runs as root implicitly). This is the one rule with actual
  control flow beyond "does this regex match this line."

### Scanning a directory: `scanner/`

```rust
pub fn scan(root: &Path, rules: &[Box<dyn Rule>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, content) in walker::walk_files(root) {
        for rule in rules {
            findings.extend(rule.scan(&path, &content));
        }
    }
    findings
}
```

[`walker.rs`](../thorn-rs/src/scanner/walker.rs) wraps `walkdir::WalkDir` with three
policies, all worth knowing before you touch it:
- Skips `.git/` directories (only — no `node_modules`, `target/`, `.venv`, etc. This
  is intentional minimalism per v0.1 scope, not an oversight).
- Skips files over 5MB (`MAX_FILE_SIZE_BYTES`) — secrets don't live in multi-MB
  blobs, and reading them whole would be wasted work.
- Skips unreadable or non-UTF-8 files silently (`.ok()?` chains) rather than
  failing the whole scan over one bad file.

### Output: `output/`

- [`json.rs`](../thorn-rs/src/output/json.rs) — builds the exact schema documented
  in CLAUDE.md (`version`, `scanned_at`, `target`, `findings[]`, `summary{}`).
  `serde_json::to_string_pretty` failure falls back to `"{}"` rather than
  panicking (same no-panic discipline as above).
- [`terminal.rs`](../thorn-rs/src/output/terminal.rs) — colored via the `colored`
  crate, severity → color mapping (CRITICAL=red, HIGH=magenta, MEDIUM=yellow,
  INFO=cyan), ends with a one-line summary count.

### CLI: `main.rs`

`clap` derive-based. Three inputs: positional `path` (default `.`), `--json`,
`--min-severity <LEVEL>`. Pipeline is: scan → filter by min-severity → sort
(severity descending, then file path) → render. Exit code is always 0 today — CI
mode (exit 1 on findings) is explicitly a **paid-tier** feature per CLAUDE.md's
monetization section and is not implemented.

## Go: `thorn-go/`

Same four-module shape, different idiom:

```
thorn-go/
├── cmd/thorn/main.go              CLI entrypoint (cobra), same pipeline as Rust
└── internal/
    ├── rules/
    │   ├── rule.go                 Rule interface, Severity, Finding
    │   ├── lines.go                  scanLines helper + relFile path normalization
    │   ├── registry.go               All() — the rule list
    │   ├── secrets.go, dotenv.go, misconfig.go   same rule split as Rust
    ├── scanner/
    │   ├── scanner.go                Scan(root, rules) -> []Finding
    │   └── walker.go                  filepath.Walk wrapper — same 3 policies
    └── output/
        ├── json.go                    same schema as Rust
        └── terminal.go                  fatih/color instead of colored
```

Structurally this is a line-for-line port of the Rust design, with the obvious Go
adaptations:
- `Rule` is an interface, implemented by empty structs (`type AwsAccessKeyID
  struct{}`), same as Rust's zero-sized unit structs.
- `Severity` is an `int` with `iota`-based ordering (`Info=0, Medium=1, High=2,
  Critical=3`) — same "declaration order is comparison order" trick, plus a custom
  `MarshalJSON` to render the uppercase string form.
- `Finding.Match` is hardcoded `"REDACTED"` in `findingAt()`, same as Rust's
  `redacted_match`.
- Regex is Go's `regexp` package (RE2 engine) — **all patterns had to be RE2-
  compatible** (no lookahead/lookbehind, no backreferences). This constrained the
  original pattern design in Rust too, so the patterns port over unchanged. If you
  ever add a rule whose "natural" regex needs backreferences, you'll need a
  different approach in Go (RE2 fundamentally can't do it) — worth checking Go
  compatibility *before* finalizing a new Rust pattern.
- Same silent-skip-on-compile-failure discipline, same reasoning
  ([`.claude/rules/go.md`](../.claude/rules/go.md): "Return errors, don't
  log-and-continue in library code" — a rule's own bad-pattern handling is the one
  deliberate exception, for the same "unit-tested literal, can't happen" reasoning
  as Rust).

### One real behavioral difference: line splitting

Rust's `str::lines()` and Go's `bufio.Scanner` (default `ScanLines` split function)
both strip `\r\n` and `\n` consistently — this was verified, not assumed, since a
divergence here would silently break Windows-authored fixture files (`\r\n` line
endings) differently between the two implementations.

## v0.2 additions: suppression, SARIF, license gating

Three new pieces, each self-contained enough to reason about independently:

- **Suppression** hooks into the existing pipeline at two points, not a new
  module of its own conceptually: `scanner::scan`/`Scan` now loads
  `.thornignore` from the scan root once (gitignore-style patterns, hand-rolled
  glob-to-regex matching — no new dependency in either language) and filters the
  walker's output before any rule ever sees a matching file; then, after each
  rule runs, `suppress::is_suppressed`/`isSuppressed` re-reads the matched line
  and drops the finding if it carries an inline `thorn-ignore` marker. Both
  checks are pure functions over `content`/`line`/`rule_id` — no state, easy to
  unit test in isolation from the walking/rule machinery. See
  `thorn-rs/src/scanner/suppress.rs` / `thorn-go/internal/scanner/suppress.go`.
  Its fixtures live in a separate `testdata/suppression/` tree, not `fixtures/`
  — see [development.md](./development.md#suppression-testing) for why.

- **SARIF output** (`output/sarif.rs` / `output/sarif.go`) is structurally a
  sibling of `output/json.rs` / `output/json.go` — same `render(target,
  findings) -> String` shape, different schema. The one thing to preserve if you
  touch it: SARIF's `message.text` must stay the rule name, never matched
  content — this is the one output format where it'd be easy to accidentally
  paste something more "detailed" in and quietly break the
  security-hardened-output guarantee described below.

- **License gating** (`license.rs` / `internal/license/license.go`) is
  deliberately narrow: a single `is_valid(key) -> bool` / `IsValid(key) bool`
  function, called from `main`/`main.go` only to decide whether
  `--fail-on-findings` is allowed to actually exit 1. It doesn't touch rules,
  scanning, or any other output format — v0.1's free, unconditional behavior is
  completely unchanged. The verification key embedded in source is a *public*
  Ed25519 key (safe to be public, even though this repo is open source) — the
  private key that mints real customer keys is deliberately kept outside the
  repo entirely. See [development.md](./development.md#testing-license-gated-features)
  for how this is tested without the real key ever touching test code.

## Why two implementations at all

Per CLAUDE.md: built in parallel specifically to benchmark Rust vs. Go for this
workload (see [`bench/compare.sh`](../bench/compare.sh) and
[project-status.md](./project-status.md)). This has a real consequence for how you
work on thorn: **a change to detection logic isn't done in one language.** The
fixture suite in `fixtures/` is shared and both implementations are asserted to
agree on every finding — first in each language's own integration test
(`thorn-rs/tests/integration.rs`, `thorn-go/internal/scanner/scanner_test.go`), then
again in CI's `cross-implementation-check` job, which runs both real binaries
against `fixtures/` and fails the build if finding counts differ.

## Security-hardened output: the one rule that touches everything

Worth restating because it's easy to accidentally violate in a new rule: **no
`Finding` field may ever carry the actual secret text.** `file` and `line` say
where to look; a human or CI system fixes it by opening that file, not by reading
the leaked value out of thorn's own output. This shaped:
- `Finding.match` / `Finding.Match` always being the literal string `"REDACTED"`
- JSON output being safe to paste into a Slack channel or public CI log
- the README's own example output explicitly calling this out
