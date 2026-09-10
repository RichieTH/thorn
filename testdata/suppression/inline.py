# thorn test fixture: inline suppression (bare thorn-ignore)

# suppressed -- should NOT be reported
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # thorn-ignore

# not suppressed -- SHOULD be reported
AWS_ACCESS_KEY_ID_2 = "AKIAIOSFODNN7EXAMPLF"
