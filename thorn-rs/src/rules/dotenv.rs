use std::path::Path;

use super::{Finding, Rule, Severity};

fn rel_file(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

pub struct DotEnvCommitted;

impl Rule for DotEnvCommitted {
    fn id(&self) -> &'static str {
        "ENV001"
    }
    fn name(&self) -> &'static str {
        ".env file committed to repo"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn scan(&self, path: &Path, _content: &str) -> Vec<Finding> {
        match path.file_name().and_then(|n| n.to_str()) {
            Some(".env") => vec![self.finding_at(&rel_file(path), 1)],
            _ => Vec::new(),
        }
    }
}

pub struct DotEnvProductionCommitted;

impl Rule for DotEnvProductionCommitted {
    fn id(&self) -> &'static str {
        "ENV002"
    }
    fn name(&self) -> &'static str {
        ".env.production committed"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn scan(&self, path: &Path, _content: &str) -> Vec<Finding> {
        match path.file_name().and_then(|n| n.to_str()) {
            Some(".env.production") => vec![self.finding_at(&rel_file(path), 1)],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn env001_matches_dot_env_filename() {
        let findings = DotEnvCommitted.scan(&PathBuf::from("fixtures/dotenv/.env"), "");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "ENV001");
    }

    #[test]
    fn env001_ignores_other_filenames() {
        let findings = DotEnvCommitted.scan(&PathBuf::from("fixtures/dotenv/.env.production"), "");
        assert!(findings.is_empty());
    }

    #[test]
    fn env002_matches_dot_env_production_filename() {
        let findings =
            DotEnvProductionCommitted.scan(&PathBuf::from("fixtures/dotenv/.env.production"), "");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "ENV002");
    }

    #[test]
    fn env002_ignores_plain_dot_env() {
        let findings = DotEnvProductionCommitted.scan(&PathBuf::from("fixtures/dotenv/.env"), "");
        assert!(findings.is_empty());
    }
}
