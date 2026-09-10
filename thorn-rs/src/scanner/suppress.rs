use regex::Regex;

/// Checks whether a finding at `line` (1-indexed) for `rule_id` is suppressed by an
/// inline `thorn-ignore` (suppresses every rule on that line) or `thorn-ignore:RULE_ID`
/// (suppresses only that rule) marker anywhere on the same line.
pub fn is_suppressed(content: &str, line: usize, rule_id: &str) -> bool {
    let Some(line_text) = content.lines().nth(line.saturating_sub(1)) else {
        return false;
    };
    let Some(idx) = line_text.find("thorn-ignore") else {
        return false;
    };
    let after = &line_text[idx + "thorn-ignore".len()..];
    match after.strip_prefix(':') {
        Some(rest) => {
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(rest.len());
            &rest[..end] == rule_id
        }
        None => true,
    }
}

/// Parses `.thornignore` content into a list of gitignore-style patterns (blank
/// lines and `#` comments skipped).
pub fn parse_ignore_patterns(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.trim_end_matches('/').to_string())
        .collect()
}

fn glob_to_regex(pattern: &str) -> Option<Regex> {
    let mut re = String::from("(?i)^");
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                re.push('\\');
                re.push(ch);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    Regex::new(&re).ok()
}

/// Checks whether `rel_path` (forward-slash relative path) is covered by any
/// pattern — either as a whole-path glob match, or as a directory prefix (a
/// pattern naming a directory ignores everything under it).
pub fn is_ignored(patterns: &[String], rel_path: &str) -> bool {
    patterns.iter().any(|pattern| {
        rel_path == pattern
            || rel_path.starts_with(&format!("{pattern}/"))
            || glob_to_regex(pattern).is_some_and(|re| re.is_match(rel_path))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_marker_suppresses_any_rule() {
        assert!(is_suppressed("key = \"x\" # thorn-ignore", 1, "SEC001"));
        assert!(is_suppressed("key = \"x\" # thorn-ignore", 1, "SEC099"));
    }

    #[test]
    fn rule_specific_marker_suppresses_only_that_rule() {
        let line = "key = \"x\" # thorn-ignore:SEC001";
        assert!(is_suppressed(line, 1, "SEC001"));
        assert!(!is_suppressed(line, 1, "SEC002"));
    }

    #[test]
    fn no_marker_is_not_suppressed() {
        assert!(!is_suppressed("key = \"x\"", 1, "SEC001"));
    }

    #[test]
    fn out_of_range_line_is_not_suppressed() {
        assert!(!is_suppressed("only one line", 5, "SEC001"));
    }

    #[test]
    fn parses_ignore_patterns_skipping_blanks_and_comments() {
        let content = "# comment\n\nignored-dir/\n*.generated.py\n";
        let patterns = parse_ignore_patterns(content);
        assert_eq!(patterns, vec!["ignored-dir", "*.generated.py"]);
    }

    #[test]
    fn directory_pattern_ignores_everything_under_it() {
        let patterns = vec!["ignored-dir".to_string()];
        assert!(is_ignored(&patterns, "ignored-dir/leaked.py"));
        assert!(!is_ignored(&patterns, "other-dir/leaked.py"));
    }

    #[test]
    fn glob_pattern_matches_whole_path() {
        let patterns = vec!["*.generated.py".to_string()];
        assert!(is_ignored(&patterns, "model.generated.py"));
        assert!(!is_ignored(&patterns, "model.py"));
    }
}
