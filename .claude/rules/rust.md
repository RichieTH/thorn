# Rust Rules (thorn-rs)

Applies to: `thorn-rs/**`

## Toolchain
- Edition: 2021
- Stable toolchain only
- MSRV: 1.75

## Dependencies (approved)
- `walkdir` — recursive directory traversal
- `regex` — pattern matching for rules
- `clap` — CLI arg parsing (derive feature)
- `serde` + `serde_json` — JSON output
- `colored` — terminal color output
- `chrono` — timestamps in output

Do not add dependencies without a clear reason. Single binary, minimal footprint.

## Code Standards
- No `unwrap()` or `expect()` outside of tests — use `?` and proper error propagation
- No `panic!()` in non-test code
- `cargo fmt` before every commit
- `cargo clippy -- -D warnings` must pass clean
- Use `thiserror` for error types if needed

## Structure
```
thorn-rs/src/
├── main.rs          # CLI entrypoint, arg parsing
├── scanner/
│   ├── mod.rs       # Scanner orchestration
│   └── walker.rs    # Directory walking
├── rules/
│   ├── mod.rs       # Rule trait + registry
│   ├── secrets.rs   # SEC* rules
│   ├── dotenv.rs    # ENV* rules
│   └── misconfig.rs # CFG* rules
└── output/
    ├── mod.rs
    ├── terminal.rs  # Colored terminal output
    └── json.rs      # JSON serialization
```

## Testing
- Unit test every rule: at least one positive match, one non-match
- Use `#[cfg(test)]` blocks in the same file as the rule
- Integration tests in `thorn-rs/tests/integration.rs` against `../fixtures/`
