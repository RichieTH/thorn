# Testing Rules

Applies to: `fixtures/**`, `bench/**`, `*_test.*`, `*_test.go`

## Fixture Philosophy
Fixtures are intentionally dirty files used to validate scanner rules.
Every rule in CLAUDE.md must have a corresponding fixture.

## Fixture Structure
```
fixtures/
├── secrets/
│   ├── aws_keys.py          # SEC001, SEC002
│   ├── api_keys.js          # SEC003
│   ├── hardcoded_password.go # SEC004
│   ├── private_key.txt      # SEC005
│   └── github_token.yaml    # SEC006
├── dotenv/
│   ├── .env                 # ENV001
│   └── .env.production      # ENV002
└── misconfigs/
    ├── Dockerfile            # CFG001
    ├── settings.py           # CFG002
    └── config.yaml           # CFG003
```

## Fixture File Requirements
- Each fixture must contain at least one true positive match for its target rule
- Each fixture should also contain at least one non-matching line (to validate no false positives)
- Fixtures use fake/obviously-invalid credentials — never real secrets
- Add a comment at the top of each fixture: `# thorn test fixture: <RULE_ID>`

## Integration Test Requirements
- Both thorn-rs and thorn-go must be tested against the same fixtures/
- Integration tests assert: correct rule_id, correct severity, correct file path
- Integration tests do NOT assert exact line numbers (fragile) — assert file + rule_id
- A clean directory (no findings) must also be tested to validate no false positives

## Benchmark Script (bench/compare.sh)
- Runs thorn-rs and thorn-go against fixtures/
- Runs each 10 times, reports median
- Outputs: binary sizes, scan times, finding counts (must match)
- Finding counts differing between implementations is a CI failure
