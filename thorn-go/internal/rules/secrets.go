package rules

import "regexp"

var (
	awsAccessKeyIDPattern     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	awsSecretAccessKeyPattern = regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?`)
	genericAPIKeyPattern      = regexp.MustCompile(`(?i)(api[_-]?key\s*[:=]\s*["'][a-z0-9_\-]{16,}["'])|(\bsk_live_[A-Za-z0-9]{16,}\b)|(\bsk-[A-Za-z0-9]{16,}\b)|(\bpk_live_[A-Za-z0-9]{16,}\b)`)
	hardcodedPasswordPattern  = regexp.MustCompile(`(?i)\b\w*pass(word)?\w*\s*=\s*['"]?[^\s'",]{4,}`)
	privateKeyBlockPattern    = regexp.MustCompile(`-----BEGIN\s+[A-Z ]*PRIVATE KEY-----`)
	gitHubGitLabTokenPattern  = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bglpat-[A-Za-z0-9_-]{16,}\b`)
)

type AwsAccessKeyID struct{}

func (AwsAccessKeyID) ID() string         { return "SEC001" }
func (AwsAccessKeyID) Name() string       { return "Hardcoded AWS Secret Key" }
func (AwsAccessKeyID) Severity() Severity { return Critical }
func (r AwsAccessKeyID) Scan(path, content string) []Finding {
	return scanLines(awsAccessKeyIDPattern, r, relFile(path), content)
}

type AwsSecretAccessKey struct{}

func (AwsSecretAccessKey) ID() string         { return "SEC002" }
func (AwsSecretAccessKey) Name() string       { return "AWS Secret Access Key" }
func (AwsSecretAccessKey) Severity() Severity { return Critical }
func (r AwsSecretAccessKey) Scan(path, content string) []Finding {
	return scanLines(awsSecretAccessKeyPattern, r, relFile(path), content)
}

type GenericAPIKey struct{}

func (GenericAPIKey) ID() string         { return "SEC003" }
func (GenericAPIKey) Name() string       { return "Generic API key pattern" }
func (GenericAPIKey) Severity() Severity { return High }
func (r GenericAPIKey) Scan(path, content string) []Finding {
	return scanLines(genericAPIKeyPattern, r, relFile(path), content)
}

type HardcodedPassword struct{}

func (HardcodedPassword) ID() string         { return "SEC004" }
func (HardcodedPassword) Name() string       { return "Hardcoded password in code" }
func (HardcodedPassword) Severity() Severity { return High }
func (r HardcodedPassword) Scan(path, content string) []Finding {
	return scanLines(hardcodedPasswordPattern, r, relFile(path), content)
}

type PrivateKeyBlock struct{}

func (PrivateKeyBlock) ID() string         { return "SEC005" }
func (PrivateKeyBlock) Name() string       { return "Private key / PEM block" }
func (PrivateKeyBlock) Severity() Severity { return Critical }
func (r PrivateKeyBlock) Scan(path, content string) []Finding {
	return scanLines(privateKeyBlockPattern, r, relFile(path), content)
}

type GitHubGitLabToken struct{}

func (GitHubGitLabToken) ID() string         { return "SEC006" }
func (GitHubGitLabToken) Name() string       { return "GitHub/GitLab personal access token" }
func (GitHubGitLabToken) Severity() Severity { return High }
func (r GitHubGitLabToken) Scan(path, content string) []Finding {
	return scanLines(gitHubGitLabTokenPattern, r, relFile(path), content)
}
