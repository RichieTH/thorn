# Go Rules (thorn-go)

Applies to: `thorn-go/**`

## Toolchain
- Go 1.25+ (bumped from 1.22+ in v0.2 by the circl dependency for ML-DSA/Dilithium)
- No CGO

## Dependencies (approved)
- `github.com/spf13/cobra` — CLI arg parsing
- `github.com/fatih/color` — terminal color output
- `github.com/cloudflare/circl` (v0.2) — pure-Go ML-DSA-65 (Dilithium) signature
  verification for `thorn verify-release`. Necessary because thorn's source is
  public: a plain shared-secret hash check can't actually be secure — asymmetric
  signing is the only offline mechanism where the public verification key can
  safely live in public source. Pure Go, no CGO, matches the "No CGO" rule below.
  Bumped Go's minimum version to 1.25 (circl's own requirement). See
  `internal/releaseverify/releaseverify.go`.
- `crypto/ed25519` (stdlib) — license-key signature verification, see
  `internal/license/license.go`.
- stdlib only for everything else (`filepath`, `regexp`, `encoding/json`, `time`)

Do not add dependencies without a clear reason.

## Code Standards
- Handle all errors explicitly — no `_` discards on errors
- `gofmt` before every commit
- `go vet ./...` must pass clean
- No global mutable state
- Return errors, don't log-and-continue in library code

## Structure
```
thorn-go/
├── cmd/thorn/
│   └── main.go          # Entrypoint
└── internal/
    ├── scanner/
    │   ├── scanner.go   # Orchestration
    │   └── walker.go    # filepath.Walk wrapper
    ├── rules/
    │   ├── rule.go      # Rule interface
    │   ├── registry.go  # Rule registry
    │   ├── secrets.go   # SEC* rules
    │   ├── dotenv.go    # ENV* rules
    │   └── misconfig.go # CFG* rules
    └── output/
        ├── terminal.go  # Colored terminal output
        └── json.go      # JSON serialization
```

## Testing
- Table-driven tests for every rule
- `_test.go` files alongside the package
- Integration test in `thorn-go/internal/scanner/scanner_test.go` against `../../fixtures/`
- `go test ./...` must pass before commit

## JSON Output
Must produce identical schema to thorn-rs. See CLAUDE.md for schema definition.
