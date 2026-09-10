use chrono::Utc;
use serde::Serialize;

use crate::rules::Finding;

#[derive(Serialize)]
struct Summary {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    info: usize,
}

#[derive(Serialize)]
struct Report<'a> {
    version: &'static str,
    scanned_at: String,
    target: String,
    findings: &'a [Finding],
    summary: Summary,
}

pub fn render(target: &str, findings: &[Finding]) -> String {
    use crate::rules::Severity;

    let summary = Summary {
        total: findings.len(),
        critical: findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        high: findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        medium: findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count(),
        info: findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count(),
    };

    let report = Report {
        version: env!("CARGO_PKG_VERSION"),
        scanned_at: Utc::now().to_rfc3339(),
        target: target.to_string(),
        findings,
        summary,
    };

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Severity;

    #[test]
    fn renders_valid_json_with_expected_summary() {
        let findings = vec![Finding {
            severity: Severity::Critical,
            rule_id: "SEC001",
            rule_name: "Hardcoded AWS Secret Key",
            file: "a.py".to_string(),
            line: 1,
            redacted_match: "REDACTED",
        }];

        let output = render(".", &findings);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["summary"]["total"], 1);
        assert_eq!(parsed["summary"]["critical"], 1);
        assert_eq!(parsed["findings"][0]["rule_id"], "SEC001");
        assert_eq!(parsed["findings"][0]["match"], "REDACTED");
    }

    #[test]
    fn renders_empty_findings_with_zeroed_summary() {
        let output = render(".", &[]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["summary"]["total"], 0);
        assert!(parsed["findings"].as_array().unwrap().is_empty());
    }
}
