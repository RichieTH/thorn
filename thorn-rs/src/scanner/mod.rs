mod suppress;
mod walker;

use std::fs;
use std::path::Path;

use crate::rules::{Finding, Rule};

fn rel_path_string(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

/// Scans `root` recursively with every rule in `rules`, returning all findings.
///
/// Two suppression mechanisms are honored automatically (no flag needed):
/// a `.thornignore` file at `root` (gitignore-style patterns, skips whole files),
/// and an inline `thorn-ignore` / `thorn-ignore:RULE_ID` comment on the matched
/// line itself.
pub fn scan(root: &Path, rules: &[Box<dyn Rule>]) -> Vec<Finding> {
    let ignore_patterns = fs::read_to_string(root.join(".thornignore"))
        .map(|content| suppress::parse_ignore_patterns(&content))
        .unwrap_or_default();

    let mut findings = Vec::new();
    for (path, content) in walker::walk_files(root) {
        if suppress::is_ignored(&ignore_patterns, &rel_path_string(root, &path)) {
            continue;
        }
        for rule in rules {
            findings.extend(
                rule.scan(&path, &content)
                    .into_iter()
                    .filter(|f| !suppress::is_suppressed(&content, f.line, f.rule_id)),
            );
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

    #[test]
    fn inline_thorn_ignore_suppresses_the_finding() {
        let dir = std::env::temp_dir().join(format!("thorn-scan-suppress-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("creds.py"),
            "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\" # thorn-ignore\n",
        )
        .unwrap();

        let findings = scan(&dir, &rules::all());
        assert!(findings.is_empty());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn thornignore_file_skips_matching_files_entirely() {
        let dir =
            std::env::temp_dir().join(format!("thorn-scan-ignorefile-{}", std::process::id()));
        let ignored_dir = dir.join("ignored-dir");
        fs::create_dir_all(&ignored_dir).unwrap();
        fs::write(dir.join(".thornignore"), "ignored-dir\n").unwrap();
        fs::write(
            ignored_dir.join("leaked.py"),
            "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n",
        )
        .unwrap();

        let findings = scan(&dir, &rules::all());
        assert!(findings.is_empty());

        fs::remove_dir_all(&dir).ok();
    }
}
