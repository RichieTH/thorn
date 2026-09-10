use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn run_thorn(target: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_thorn"))
        .arg("--json")
        .arg(target)
        .output()
        .expect("failed to run thorn binary");
    assert!(
        output.status.success(),
        "thorn exited non-zero: {:?}",
        output.status
    );
    serde_json::from_slice(&output.stdout).expect("thorn produced invalid JSON")
}

fn rule_ids_for_file(report: &Value, file_suffix: &str) -> HashSet<String> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| {
            f["file"]
                .as_str()
                .unwrap()
                .replace('\\', "/")
                .ends_with(file_suffix)
        })
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn scans_fixtures_and_finds_every_expected_rule() {
    let report = run_thorn("../fixtures");

    let expected: &[(&str, &[&str])] = &[
        ("fixtures/secrets/aws_keys.py", &["SEC001", "SEC002"]),
        ("fixtures/secrets/api_keys.js", &["SEC003", "SEC004"]),
        ("fixtures/secrets/github_token.yaml", &["SEC006"]),
        ("fixtures/secrets/private_key.txt", &["SEC005"]),
        ("fixtures/dotenv/.env", &["ENV001"]),
        ("fixtures/dotenv/.env.production", &["ENV002"]),
        ("fixtures/misconfigs/Dockerfile", &["CFG001"]),
        ("fixtures/misconfigs/settings.py", &["CFG002", "CFG003"]),
    ];

    for (file_suffix, rule_ids) in expected {
        let found = rule_ids_for_file(&report, file_suffix);
        for rule_id in *rule_ids {
            assert!(
                found.contains(*rule_id),
                "expected {} to be found in {}, but only found {:?}",
                rule_id,
                file_suffix,
                found
            );
        }
    }
}

#[test]
fn json_report_has_well_formed_summary() {
    let report = run_thorn("../fixtures");
    let findings = report["findings"].as_array().unwrap();
    let summary = &report["summary"];

    let critical = summary["critical"].as_u64().unwrap();
    let high = summary["high"].as_u64().unwrap();
    let medium = summary["medium"].as_u64().unwrap();
    let info = summary["info"].as_u64().unwrap();
    let total = summary["total"].as_u64().unwrap();

    assert_eq!(critical + high + medium + info, total);
    assert_eq!(total, findings.len() as u64);
    assert!(
        total > 0,
        "expected findings scanning the dirty fixtures dir"
    );
}

#[test]
fn clean_directory_produces_no_findings() {
    let dir = std::env::temp_dir().join(format!("thorn-integration-clean-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("readme.txt"), "nothing interesting here\n").unwrap();

    let report = run_thorn(dir.to_str().unwrap());
    assert_eq!(report["summary"]["total"], 0);
    assert!(report["findings"].as_array().unwrap().is_empty());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn min_severity_filters_out_lower_severity_findings() {
    let output = Command::new(env!("CARGO_BIN_EXE_thorn"))
        .arg("--json")
        .arg("--min-severity")
        .arg("CRITICAL")
        .arg("../fixtures")
        .output()
        .expect("failed to run thorn binary");
    assert!(output.status.success());

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f["severity"] == "CRITICAL"));
}

#[test]
fn fixtures_directory_exists() {
    assert!(
        Path::new("../fixtures").is_dir(),
        "expected shared fixtures/ dir at repo root"
    );
}

#[test]
fn sarif_output_is_well_formed() {
    let output = Command::new(env!("CARGO_BIN_EXE_thorn"))
        .arg("--sarif")
        .arg("../fixtures")
        .output()
        .expect("failed to run thorn binary");
    assert!(output.status.success());

    let report: Value =
        serde_json::from_slice(&output.stdout).expect("thorn produced invalid SARIF JSON");
    assert_eq!(report["version"], "2.1.0");
    assert!(!report["runs"][0]["results"].as_array().unwrap().is_empty());
}

#[test]
fn json_and_sarif_together_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_thorn"))
        .arg("--json")
        .arg("--sarif")
        .arg("../fixtures")
        .output()
        .expect("failed to run thorn binary");
    assert!(!output.status.success());
}

#[test]
fn suppression_testdata_exists() {
    assert!(
        Path::new("../testdata/suppression").is_dir(),
        "expected ../testdata/suppression fixture dir"
    );
}

#[test]
fn thornignore_and_inline_suppression_actually_suppress() {
    let report = run_thorn("../testdata/suppression");
    let findings = report["findings"].as_array().unwrap();

    // inline.py: bare thorn-ignore suppresses one key, the other (unsuppressed) is reported.
    let inline_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f["file"]
                .as_str()
                .unwrap()
                .replace('\\', "/")
                .ends_with("inline.py")
        })
        .collect();
    assert_eq!(
        inline_findings.len(),
        1,
        "expected exactly one unsuppressed finding in inline.py"
    );

    // rule-specific.py: thorn-ignore:SEC001 suppresses only SEC001, CFG003 (localhost) still reported.
    let rule_specific_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f["file"]
                .as_str()
                .unwrap()
                .replace('\\', "/")
                .ends_with("rule-specific.py")
        })
        .collect();
    assert_eq!(rule_specific_findings.len(), 1);
    assert_eq!(rule_specific_findings[0]["rule_id"], "CFG003");

    // .thornignore skips ignored-dir/ entirely -- its leaked secret must never appear.
    assert!(findings.iter().all(|f| !f["file"]
        .as_str()
        .unwrap()
        .replace('\\', "/")
        .contains("ignored-dir")));
}

#[test]
fn fail_on_findings_without_key_exits_2_with_message() {
    let output = Command::new(env!("CARGO_BIN_EXE_thorn"))
        .arg("--fail-on-findings")
        .arg("../fixtures")
        .output()
        .expect("failed to run thorn binary");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("license key"), "stderr was: {stderr}");
}

#[test]
fn fail_on_findings_with_invalid_key_exits_2_with_message() {
    let output = Command::new(env!("CARGO_BIN_EXE_thorn"))
        .arg("--fail-on-findings")
        .arg("--license-key")
        .arg("not-a-valid-key")
        .arg("../fixtures")
        .output()
        .expect("failed to run thorn binary");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("license key"), "stderr was: {stderr}");
}

#[test]
fn without_fail_on_findings_exits_0_regardless_of_findings() {
    let output = Command::new(env!("CARGO_BIN_EXE_thorn"))
        .arg("--json")
        .arg("../fixtures")
        .output()
        .expect("failed to run thorn binary");
    assert!(output.status.success());
}
