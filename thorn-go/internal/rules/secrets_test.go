package rules

import "testing"

func TestAwsAccessKeyID(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		matches bool
	}{
		{"matches AWS access key", `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`, true},
		{"ignores unrelated line", `region = "us-east-1"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := AwsAccessKeyID{}.Scan("test.py", tc.line)
			if tc.matches && len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if !tc.matches && len(findings) != 0 {
				t.Fatalf("expected no findings, got %d", len(findings))
			}
			if tc.matches && findings[0].RuleID != "SEC001" {
				t.Errorf("expected rule_id SEC001, got %s", findings[0].RuleID)
			}
		})
	}
}

func TestAwsSecretAccessKey(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		matches bool
	}{
		{"matches AWS secret key", `AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, true},
		{"ignores unrelated line", `bucket_name = "my-test-bucket"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := AwsSecretAccessKey{}.Scan("test.py", tc.line)
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
		})
	}
}

func TestGenericAPIKey(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		matches bool
	}{
		{"matches apiKey", `apiKey: "sk-abc123def456ghi789jkl012mno345pqr678stu",`, true},
		{"ignores endpoint url", `apiEndpoint: "https://api.example.com/v1",`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := GenericAPIKey{}.Scan("test.js", tc.line)
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
		})
	}
}

func TestHardcodedPassword(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		matches bool
	}{
		{"matches password= inside string", `dbPassword: "password=SuperSecret123!",`, true},
		{"matches admin_password", `adminPass: "admin_password = 'hunter2'",`, true},
		{"ignores unrelated field", `timeout: 3000,`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := HardcodedPassword{}.Scan("test.js", tc.line)
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
		})
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		matches bool
	}{
		{"matches RSA private key header", `-----BEGIN RSA PRIVATE KEY-----`, true},
		{"ignores public key", `public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB user@host"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := PrivateKeyBlock{}.Scan("test.txt", tc.line)
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
		})
	}
}

func TestGitHubGitLabToken(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		matches bool
	}{
		{"matches github token", `github_token: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"`, true},
		{"matches gitlab token", `gitlab_token: "glpat-xxxxxxxxxxxxxxxxxxxx"`, true},
		{"ignores repo url", `repo: "https://github.com/org/repo"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := GitHubGitLabToken{}.Scan("test.yaml", tc.line)
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
		})
	}
}

func TestFindingsNeverExposeActualMatchText(t *testing.T) {
	findings := AwsAccessKeyID{}.Scan("test.py", `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Match != "REDACTED" {
		t.Errorf("expected redacted match, got %q", findings[0].Match)
	}
}
