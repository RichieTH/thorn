use std::path::Path;

use regex::Regex;

use super::{Finding, Rule, Severity};

fn rel_file(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

pub struct DockerfileUserRoot;

impl Rule for DockerfileUserRoot {
    fn id(&self) -> &'static str {
        "CFG001"
    }
    fn name(&self) -> &'static str {
        "Dockerfile USER root"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        let is_dockerfile = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("Dockerfile"))
            .unwrap_or(false);
        if !is_dockerfile {
            return Vec::new();
        }

        let (Ok(user_root), Ok(user_any)) = (
            Regex::new(r"(?i)^\s*USER\s+root\b"),
            Regex::new(r"(?i)^\s*USER\s+\S+"),
        ) else {
            return Vec::new();
        };

        for (idx, line) in content.lines().enumerate() {
            if user_root.is_match(line) {
                return vec![self.finding_at(&rel_file(path), idx + 1)];
            }
        }

        if !content.lines().any(|line| user_any.is_match(line)) {
            let last_line = content.lines().count().max(1);
            return vec![self.finding_at(&rel_file(path), last_line)];
        }

        Vec::new()
    }
}

pub struct DebugModeEnabled;

impl Rule for DebugModeEnabled {
    fn id(&self) -> &'static str {
        "CFG002"
    }
    fn name(&self) -> &'static str {
        "Debug mode enabled in config"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        let Ok(pattern) = Regex::new(r"(?i)\b(debug|flask_debug|debug_mode)\s*=\s*(true|1)\b")
        else {
            return Vec::new();
        };
        content
            .lines()
            .enumerate()
            .filter(|(_, line)| pattern.is_match(line))
            .map(|(idx, _)| self.finding_at(&rel_file(path), idx + 1))
            .collect()
    }
}

pub struct HardcodedLocalhost;

impl Rule for HardcodedLocalhost {
    fn id(&self) -> &'static str {
        "CFG003"
    }
    fn name(&self) -> &'static str {
        "Hardcoded localhost/127.0.0.1"
    }
    fn severity(&self) -> Severity {
        Severity::Info
    }
    fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        let Ok(pattern) = Regex::new(r"(?i)(127\.0\.0\.1|localhost)") else {
            return Vec::new();
        };
        content
            .lines()
            .enumerate()
            .filter(|(_, line)| pattern.is_match(line))
            .map(|(idx, _)| self.finding_at(&rel_file(path), idx + 1))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn cfg001_matches_user_root() {
        let content = "FROM ubuntu:22.04\nUSER root\nCMD [\"./server\"]";
        let findings = DockerfileUserRoot.scan(&PathBuf::from("Dockerfile"), content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "CFG001");
    }

    #[test]
    fn cfg001_ignores_non_root_user() {
        let content = "FROM ubuntu:22.04\nUSER appuser\nCMD [\"./server\"]";
        let findings = DockerfileUserRoot.scan(&PathBuf::from("Dockerfile"), content);
        assert!(findings.is_empty());
    }

    #[test]
    fn cfg001_flags_missing_user_directive() {
        let content = "FROM ubuntu:22.04\nCMD [\"./server\"]";
        let findings = DockerfileUserRoot.scan(&PathBuf::from("Dockerfile"), content);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn cfg001_ignores_non_dockerfile() {
        let findings = DockerfileUserRoot.scan(&PathBuf::from("USER root notes.txt"), "USER root");
        assert!(findings.is_empty());
    }

    #[test]
    fn cfg002_matches_debug_true() {
        let findings = DebugModeEnabled.scan(&PathBuf::from("settings.py"), "DEBUG = True");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn cfg002_matches_flask_debug() {
        let findings = DebugModeEnabled.scan(&PathBuf::from("settings.py"), "FLASK_DEBUG = 1");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn cfg002_ignores_non_matching_line() {
        let findings = DebugModeEnabled.scan(&PathBuf::from("settings.py"), "LOG_LEVEL = \"INFO\"");
        assert!(findings.is_empty());
    }

    #[test]
    fn cfg003_matches_localhost_ip() {
        let findings = HardcodedLocalhost.scan(
            &PathBuf::from("settings.py"),
            "DATABASE_HOST = \"127.0.0.1\"",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn cfg003_matches_localhost_name() {
        let findings = HardcodedLocalhost.scan(
            &PathBuf::from("settings.py"),
            "REDIS_URL = \"redis://localhost:6379\"",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn cfg003_ignores_non_matching_line() {
        let findings =
            HardcodedLocalhost.scan(&PathBuf::from("settings.py"), "MAX_CONNECTIONS = 100");
        assert!(findings.is_empty());
    }
}
