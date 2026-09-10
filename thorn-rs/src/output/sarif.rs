use serde::Serialize;
use std::collections::BTreeMap;

use crate::rules::{Finding, Severity};

const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

#[derive(Serialize)]
struct SarifReport {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: &'static str,
    version: &'static str,
    rules: Vec<RuleDescriptor>,
}

#[derive(Serialize)]
struct RuleDescriptor {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: ShortDescription,
}

#[derive(Serialize)]
struct ShortDescription {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: Message,
    locations: Vec<Location>,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: usize,
}

/// Maps thorn's severity to SARIF's `level`: CRITICAL/HIGH -> error, MEDIUM ->
/// warning, INFO -> note.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Info => "note",
    }
}

/// Renders findings as a SARIF 2.1.0 log, for upload to GitHub code scanning
/// (`github/codeql-action/upload-sarif`) or any other SARIF-consuming tool.
/// `target` is accepted for signature symmetry with the other output renderers but
/// SARIF's schema has no place for it — findings' own `locations` already carry
/// per-result paths.
pub fn render(_target: &str, findings: &[Finding]) -> String {
    let mut rule_descriptors: BTreeMap<&'static str, RuleDescriptor> = BTreeMap::new();
    let mut results = Vec::with_capacity(findings.len());

    for finding in findings {
        rule_descriptors
            .entry(finding.rule_id)
            .or_insert_with(|| RuleDescriptor {
                id: finding.rule_id.to_string(),
                name: finding.rule_name.to_string(),
                short_description: ShortDescription {
                    text: finding.rule_name.to_string(),
                },
            });

        results.push(SarifResult {
            rule_id: finding.rule_id.to_string(),
            level: sarif_level(finding.severity),
            message: Message {
                text: finding.rule_name.to_string(),
            },
            locations: vec![Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: finding.file.clone(),
                    },
                    region: Region {
                        start_line: finding.line,
                    },
                },
            }],
        });
    }

    let report = SarifReport {
        version: "2.1.0",
        schema: SARIF_SCHEMA,
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "thorn",
                    version: env!("CARGO_PKG_VERSION"),
                    rules: rule_descriptors.into_values().collect(),
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_id: &'static str, rule_name: &'static str, severity: Severity) -> Finding {
        Finding {
            severity,
            rule_id,
            rule_name,
            file: "a.py".to_string(),
            line: 7,
            redacted_match: "REDACTED",
        }
    }

    #[test]
    fn renders_valid_sarif_with_correct_shape() {
        let findings = vec![finding(
            "SEC001",
            "Hardcoded AWS Secret Key",
            Severity::Critical,
        )];
        let output = render(".", &findings);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["$schema"], SARIF_SCHEMA);
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "thorn");
        assert_eq!(parsed["runs"][0]["results"][0]["ruleId"], "SEC001");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "a.py"
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            7
        );
    }

    #[test]
    fn maps_severities_to_correct_sarif_levels() {
        assert_eq!(sarif_level(Severity::Critical), "error");
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Info), "note");
    }

    #[test]
    fn never_leaks_match_text_only_rule_name() {
        let findings = vec![finding(
            "SEC001",
            "Hardcoded AWS Secret Key",
            Severity::Critical,
        )];
        let output = render(".", &findings);
        assert!(!output.contains("AKIA"));
        assert!(output.contains("Hardcoded AWS Secret Key"));
    }

    #[test]
    fn empty_findings_produces_empty_results_and_rules() {
        let output = render(".", &[]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["runs"][0]["results"].as_array().unwrap().is_empty());
        assert!(parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn dedupes_rule_descriptors_across_multiple_findings_of_same_rule() {
        let findings = vec![
            finding("SEC001", "Hardcoded AWS Secret Key", Severity::Critical),
            finding("SEC001", "Hardcoded AWS Secret Key", Severity::Critical),
        ];
        let output = render(".", &findings);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 2);
    }
}
