use colored::{Color, Colorize};

use crate::rules::{Finding, Severity};

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::Magenta,
        Severity::Medium => Color::Yellow,
        Severity::Info => Color::Cyan,
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Info => "INFO",
    }
}

pub fn render(target: &str, findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str(&format!("Scanning {}\n\n", target));

    if findings.is_empty() {
        out.push_str(&format!("{}\n", "No findings — clean scan.".green()));
        return out;
    }

    for finding in findings {
        let label = severity_label(finding.severity)
            .color(severity_color(finding.severity))
            .bold();
        out.push_str(&format!(
            "[{}] {} — {}:{} ({})\n",
            label, finding.rule_name, finding.file, finding.line, finding.rule_id
        ));
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    out.push_str(&format!(
        "\n{} findings: {} critical, {} high, {} medium, {} info\n",
        findings.len(),
        critical.to_string().red(),
        high.to_string().magenta(),
        medium.to_string().yellow(),
        info.to_string().cyan(),
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_findings_reports_clean_scan() {
        let output = render(".", &[]);
        assert!(output.contains("No findings"));
    }

    #[test]
    fn findings_are_listed_with_rule_id_and_location() {
        let findings = vec![Finding {
            severity: Severity::Critical,
            rule_id: "SEC001",
            rule_name: "Hardcoded AWS Secret Key",
            file: "a.py".to_string(),
            line: 7,
            redacted_match: "REDACTED",
        }];
        let output = render(".", &findings);
        assert!(output.contains("SEC001"));
        assert!(output.contains("a.py:7"));
        assert!(output.contains("1 findings"));
    }
}
