# thorn documentation

This is the context library for working on thorn — a security-hardened repo scanner
CLI, built in parallel as `thorn-rs` (Rust) and `thorn-go` (Go). If you're new here,
read these in order:

1. **[architecture.md](./architecture.md)** — how the codebase is shaped, in both
   languages, and the design decisions that constrain any change you make.
2. **[rules-reference.md](./rules-reference.md)** — the full catalog of detection
   rules: what each one matches, its exact pattern, and its fixture.
3. **[development.md](./development.md)** — how to build, test, and lint locally;
   how to add a new rule end-to-end; coding standards for each language.
4. **[ci-cd.md](./ci-cd.md)** — what the CI and release pipelines actually do, plus
   the non-obvious gotchas that have already bitten this project once each.
5. **[project-status.md](./project-status.md)** — what's shipped, what's
   deliberately deferred, and what the documented-but-unbuilt roadmap looks like.

## Where the *authoritative* rules live

This `docs/` directory is reference material for humans (and future AI sessions)
to get oriented quickly. The actual binding project rules are:

- **[../CLAUDE.md](../CLAUDE.md)** — scope, schema, rule ID table, coding standards,
  distribution/monetization plan. This is the source of truth; if anything in
  `docs/` ever contradicts it, CLAUDE.md wins and these docs are stale.
- **[../.claude/rules/rust.md](../.claude/rules/rust.md)**,
  **[go.md](../.claude/rules/go.md)**, **[testing.md](../.claude/rules/testing.md)**
  — per-area coding/testing rules, auto-applied by path.

## Quick orientation

```
thorn/
├── thorn-rs/           Rust implementation — see architecture.md
├── thorn-go/            Go implementation — see architecture.md
├── fixtures/            Shared dirty test repos both implementations scan
├── bench/compare.sh     Cross-implementation benchmark + agreement check
├── .github/workflows/   CI (every push) + Release (on v* tags) — see ci-cd.md
├── CLAUDE.md             Authoritative project spec
└── docs/                 You are here
```

Both implementations are functionally identical by design: same rule IDs, same
severities, same JSON schema, same fixture suite. A change to detection logic in
one language is not done until the equivalent change exists in the other and
`bench/compare.sh` reports matching finding counts.
