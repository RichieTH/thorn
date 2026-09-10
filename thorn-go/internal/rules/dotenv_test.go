package rules

import "testing"

func TestDotEnvCommitted(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		matches bool
	}{
		{"matches .env filename", "fixtures/dotenv/.env", true},
		{"ignores .env.production", "fixtures/dotenv/.env.production", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := DotEnvCommitted{}.Scan(tc.path, "")
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
			if tc.matches && findings[0].RuleID != "ENV001" {
				t.Errorf("expected rule_id ENV001, got %s", findings[0].RuleID)
			}
		})
	}
}

func TestDotEnvProductionCommitted(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		matches bool
	}{
		{"matches .env.production filename", "fixtures/dotenv/.env.production", true},
		{"ignores plain .env", "fixtures/dotenv/.env", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := DotEnvProductionCommitted{}.Scan(tc.path, "")
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
			if tc.matches && findings[0].RuleID != "ENV002" {
				t.Errorf("expected rule_id ENV002, got %s", findings[0].RuleID)
			}
		})
	}
}
