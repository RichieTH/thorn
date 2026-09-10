use std::path::Path;

use regex::Regex;

use super::{Finding, Rule, Severity};

/// Scans each line of `content` against `pattern`, producing one finding per matching line.
/// If `pattern` fails to compile the rule simply finds nothing, rather than panicking a scan
/// over an unrelated, unfixable regex bug — all patterns here are unit-tested literals.
fn scan_lines(pattern: &str, rule: &dyn Rule, file: &str, content: &str) -> Vec<Finding> {
    let Ok(pattern) = Regex::new(pattern) else {
        return Vec::new();
    };
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| pattern.is_match(line))
        .map(|(idx, _)| rule.finding_at(file, idx + 1))
        .collect()
}

fn rel_file(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

pub struct AwsAccessKeyId;

impl Rule for AwsAccessKeyId {
    fn id(&self) -> &'static str {
        "SEC001"
    }
    fn name(&self) -> &'static str {
        "Hardcoded AWS Secret Key"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        scan_lines(r"\bAKIA[0-9A-Z]{16}\b", self, &rel_file(path), content)
    }
}

pub struct AwsSecretAccessKey;

impl Rule for AwsSecretAccessKey {
    fn id(&self) -> &'static str {
        "SEC002"
    }
    fn name(&self) -> &'static str {
        "AWS Secret Access Key"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        scan_lines(
            r#"(?i)aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?"#,
            self,
            &rel_file(path),
            content,
        )
    }
}

pub struct GenericApiKey;

impl Rule for GenericApiKey {
    fn id(&self) -> &'static str {
        "SEC003"
    }
    fn name(&self) -> &'static str {
        "Generic API key pattern"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        scan_lines(
            r#"(?i)(api[_-]?key\s*[:=]\s*["'][a-z0-9_\-]{16,}["'])|(\bsk_live_[A-Za-z0-9]{16,}\b)|(\bsk-[A-Za-z0-9]{16,}\b)|(\bpk_live_[A-Za-z0-9]{16,}\b)"#,
            self,
            &rel_file(path),
            content,
        )
    }
}

pub struct HardcodedPassword;

impl Rule for HardcodedPassword {
    fn id(&self) -> &'static str {
        "SEC004"
    }
    fn name(&self) -> &'static str {
        "Hardcoded password in code"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        scan_lines(
            r#"(?i)\b\w*pass(word)?\w*\s*=\s*['"]?[^\s'",]{4,}"#,
            self,
            &rel_file(path),
            content,
        )
    }
}

pub struct PrivateKeyBlock;

impl Rule for PrivateKeyBlock {
    fn id(&self) -> &'static str {
        "SEC005"
    }
    fn name(&self) -> &'static str {
        "Private key / PEM block"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        scan_lines(
            r"-----BEGIN\s+[A-Z ]*PRIVATE KEY-----",
            self,
            &rel_file(path),
            content,
        )
    }
}

pub struct GitHubGitLabToken;

impl Rule for GitHubGitLabToken {
    fn id(&self) -> &'static str {
        "SEC006"
    }
    fn name(&self) -> &'static str {
        "GitHub/GitLab personal access token"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        scan_lines(
            r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bglpat-[A-Za-z0-9_-]{16,}\b",
            self,
            &rel_file(path),
            content,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scan(rule: &dyn Rule, content: &str) -> Vec<Finding> {
        rule.scan(&PathBuf::from("test.txt"), content)
    }

    #[test]
    fn sec001_matches_aws_access_key() {
        let findings = scan(
            &AwsAccessKeyId,
            "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SEC001");
    }

    #[test]
    fn sec001_ignores_non_matching_line() {
        let findings = scan(&AwsAccessKeyId, "region = \"us-east-1\"");
        assert!(findings.is_empty());
    }

    #[test]
    fn sec002_matches_aws_secret_key() {
        let findings = scan(
            &AwsSecretAccessKey,
            "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sec002_ignores_non_matching_line() {
        let findings = scan(&AwsSecretAccessKey, "bucket_name = \"my-test-bucket\"");
        assert!(findings.is_empty());
    }

    #[test]
    fn sec003_matches_generic_api_key() {
        let findings = scan(
            &GenericApiKey,
            "apiKey: \"sk-abc123def456ghi789jkl012mno345pqr678stu\",",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sec003_ignores_non_matching_line() {
        let findings = scan(
            &GenericApiKey,
            "apiEndpoint: \"https://api.example.com/v1\",",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn sec004_matches_hardcoded_password() {
        let findings = scan(
            &HardcodedPassword,
            "dbPassword: \"password=SuperSecret123!\",",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sec004_matches_admin_password() {
        let findings = scan(
            &HardcodedPassword,
            "adminPass: \"admin_password = 'hunter2'\",",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sec004_ignores_non_matching_line() {
        let findings = scan(&HardcodedPassword, "timeout: 3000,");
        assert!(findings.is_empty());
    }

    #[test]
    fn sec005_matches_private_key_block() {
        let findings = scan(&PrivateKeyBlock, "-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sec005_ignores_public_key() {
        let findings = scan(
            &PrivateKeyBlock,
            "public_key = \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB user@host\"",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn sec006_matches_github_token() {
        let findings = scan(
            &GitHubGitLabToken,
            "github_token: \"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456\"",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sec006_matches_gitlab_token() {
        let findings = scan(
            &GitHubGitLabToken,
            "gitlab_token: \"glpat-xxxxxxxxxxxxxxxxxxxx\"",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sec006_ignores_repo_url() {
        let findings = scan(&GitHubGitLabToken, "repo: \"https://github.com/org/repo\"");
        assert!(findings.is_empty());
    }

    #[test]
    fn findings_never_expose_actual_match_text() {
        let findings = scan(
            &AwsAccessKeyId,
            "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"",
        );
        assert_eq!(findings[0].redacted_match, "REDACTED");
    }
}
