# thorn test fixture: inline suppression (rule-specific thorn-ignore:RULE_ID)

# SEC001 suppressed specifically -- should NOT be reported
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # thorn-ignore:SEC001

# a different rule, not suppressed -- SHOULD still be reported
DATABASE_HOST = "127.0.0.1"
