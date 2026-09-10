use serde::Serialize;
use std::path::Path;

mod dotenv;
mod misconfig;
mod secrets;

/// Severity ordered ascending so `>=` comparisons work for `--min-severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
#[clap(rename_all = "UPPER")]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub file: String,
    pub line: usize,
    /// Never the actual matched text — output is security-hardened by default.
    #[serde(rename = "match")]
    pub redacted_match: &'static str,
}

pub trait Rule {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    /// Scan a single file's content, returning zero or more findings.
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding>;

    fn finding_at(&self, file: &str, line: usize) -> Finding {
        Finding {
            severity: self.severity(),
            rule_id: self.id(),
            rule_name: self.name(),
            file: file.to_string(),
            line,
            redacted_match: "REDACTED",
        }
    }
}

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(secrets::AwsAccessKeyId),
        Box::new(secrets::AwsSecretAccessKey),
        Box::new(secrets::GenericApiKey),
        Box::new(secrets::HardcodedPassword),
        Box::new(secrets::PrivateKeyBlock),
        Box::new(secrets::GitHubGitLabToken),
        Box::new(dotenv::DotEnvCommitted),
        Box::new(dotenv::DotEnvProductionCommitted),
        Box::new(misconfig::DockerfileUserRoot),
        Box::new(misconfig::DebugModeEnabled),
        Box::new(misconfig::HardcodedLocalhost),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Info);
    }

    #[test]
    fn all_rules_have_unique_ids() {
        let rules = all();
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "duplicate rule id found");
    }
}
