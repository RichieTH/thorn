# Go Rules (thorn-go)

Applies to: `thorn-go/**`

## Toolchain
- Go 1.22+
- No CGO

## Dependencies (approved)
- `github.com/spf13/cobra` — CLI arg parsing
- `github.com/fatih/color` — terminal color output
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
