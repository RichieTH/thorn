mod walker;

use std::path::Path;

use crate::rules::{Finding, Rule};

/// Scans `root` recursively with every rule in `rules`, returning all findings.
pub fn scan(root: &Path, rules: &[Box<dyn Rule>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, content) in walker::walk_files(root) {
        for rule in rules {
            findings.extend(rule.scan(&path, &content));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules;
    use std::fs;

    #[test]
    fn scans_directory_and_finds_seeded_secret() {
        let dir = std::env::temp_dir().join(format!("thorn-scan-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("creds.py"),
            "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n",
        )
        .unwrap();

        let findings = scan(&dir, &rules::all());
        assert!(findings.iter().any(|f| f.rule_id == "SEC001"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clean_directory_produces_no_findings() {
        let dir = std::env::temp_dir().join(format!("thorn-scan-clean-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("readme.txt"), "nothing interesting here\n").unwrap();

        let findings = scan(&dir, &rules::all());
        assert!(findings.is_empty());

        fs::remove_dir_all(&dir).ok();
    }
}
