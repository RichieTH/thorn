# Project status

## Shipped: v0.1.0

Tagged and released at
[github.com/RichieTH/thorn/releases/tag/v0.1.0](https://github.com/RichieTH/thorn/releases/tag/v0.1.0).
All 6 v0.1 scope items from CLAUDE.md are complete:

- [x] Recursive directory scan
- [x] Hardcoded secrets detection (SEC001–006)
- [x] Committed `.env` file detection (ENV001–002)
- [x] Common misconfig detection (CFG001–003)
- [x] Severity-leveled terminal output
- [x] `--json` flag

Plus everything CLAUDE.md's "Current Status" checklist tracked beyond the core
scope: both implementations, fixtures, unit tests, integration tests, benchmark
script, CI, release workflow, and a README with real (verified, not fabricated)
install instructions.

Distribution today: **direct binary download** (all 12 win/linux/mac × amd64/arm64
× {rust,go} builds) and **`go install`** both work and have been verified by
actually running the resulting binary, not just trusting a green build. **Not**
live: `cargo install thorn-scan` (name reserved on crates.io, never published) and
the Homebrew tap (never created).

## What's deliberately *not* built yet

These aren't gaps found by accident — they're explicitly out of v0.1 scope per
CLAUDE.md ("DO NOT EXPAND UNTIL DONE"), listed here so the next person doesn't
rediscover the same scope boundary by surprise:

- **Monetization** (CLAUDE.md's "Monetization" section): a free/paid rule split
  (SEC001, ENV001, CFG001 free; everything else paid), a $29 one-time or $9/mo
  paid tier, offline license-key validation (hash check, no network call), sold via
  Lemon Squeezy. **None of this exists in code.** All 11 rules currently run
  unconditionally regardless of any license state — see the tier column in
  [rules-reference.md](./rules-reference.md). There is no license-key parsing,
  no gating logic, nothing to disable.
- **CI mode** (exit code 1 on findings) — documented as a paid-tier feature.
  `thorn`'s exit code is always 0 today, findings or not. This is a deliberate
  scope decision: implementing exit-code gating without the license system behind
  it would mean building half a monetization feature for free, which contradicts
  the plan.
- **crates.io / Homebrew publishing** — see above; blocked on someone actually
  running `cargo publish` and setting up a tap repo, not a technical blocker.
- **A real demo GIF/asciinema recording** for the README — a static captured-output
  block stands in for now; recording an actual terminal session needs a human at a
  real terminal, not something scriptable from here.
- **`.env.local`, `.env.development`, etc.** — ENV001/002 match only the exact
  filenames `.env` and `.env.production`, not the broader family of dotenv variants.
  Reasonable small addition if ever needed, not done.
- **Directory skip-list beyond `.git`** — the walker doesn't skip `node_modules/`,
  `target/`, `.venv/`, etc. Fine at v0.1 scale; would matter for scan speed on a
  large real-world repo.

## v2+ — documented in CLAUDE.md, not scoped for thorn specifically

CLAUDE.md's v2/v3/v4 sections describe a **different, unrelated project** (a
Bangkok cannabis-cafe check-in app called Highspot) that happened to share a
`CLAUDE.md` path with this one early in the session. **Ignore those sections when
planning thorn's roadmap** — they don't apply here. thorn's own forward-looking
plan lives entirely in CLAUDE.md's "Distribution Plan" and "Monetization" sections
(summarized above), not in versioned v2/v3/v4 milestones.

## Deciding what's next

The two directions implied by what's documented-but-unbuilt are meaningfully
different chunks of work, worth explicitly choosing between rather than defaulting:

1. **Finish distribution** — publish to crates.io, set up the Homebrew tap. Low
   effort, mostly account/process work (crates.io publish, `homebrew-tap` repo
   creation), makes the README's remaining "coming soon" lines actually true.
2. **Build monetization** — license-key generation + offline validation, the
   free/paid rule gate, Lemon Squeezy integration, CI-mode exit codes. Meaningfully
   larger: new crypto/validation logic in both languages, a key-generation side
   process, payment integration, and a design decision about what the free tier
   actually needs to still be "enough to be useful" (CLAUDE.md's own phrase).
3. **New rules / broader detection** — the fixture-driven, dual-language pattern
   is now proven out end-to-end (see [development.md](./development.md#adding-a-new-rule)
   for the checklist); adding rules is now the cheapest kind of change available.

None of these block each other, but (2) in particular is a scope decision worth
making explicitly before starting — it changes what "done" means for a lot of
adjacent code (exit codes, CLI flags for license keys, output formatting when a
rule is gated).
