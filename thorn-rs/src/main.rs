mod license;
mod output;
mod rules;
mod scanner;

use std::path::PathBuf;

use clap::Parser;

use rules::Severity;

/// Security-hardened repo scanner — detects hardcoded secrets, committed .env files,
/// and common misconfigurations.
#[derive(Parser)]
#[command(name = "thorn", version)]
struct Cli {
    /// Directory to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Emit machine-readable JSON instead of colored terminal output
    #[arg(long)]
    json: bool,

    /// Emit a SARIF 2.1.0 log instead of colored terminal output
    #[arg(long, conflicts_with = "json")]
    sarif: bool,

    /// Only report findings at or above this severity
    #[arg(long, value_enum)]
    min_severity: Option<Severity>,

    /// Exit with code 1 if any findings remain after filtering (paid feature —
    /// requires --license-key or THORN_LICENSE_KEY)
    #[arg(long)]
    fail_on_findings: bool,

    /// License key unlocking --fail-on-findings (falls back to THORN_LICENSE_KEY)
    #[arg(long)]
    license_key: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if !cli.path.exists() {
        eprintln!("thorn: path not found: {}", cli.path.display());
        std::process::exit(1);
    }

    if cli.fail_on_findings {
        let key = cli
            .license_key
            .clone()
            .or_else(|| std::env::var("THORN_LICENSE_KEY").ok());
        let valid = key.as_deref().is_some_and(license::is_valid);
        if !valid {
            eprintln!(
                "thorn: --fail-on-findings requires a valid license key (set --license-key or THORN_LICENSE_KEY)"
            );
            std::process::exit(2);
        }
    }

    let mut findings = scanner::scan(&cli.path, &rules::all());

    if let Some(min) = cli.min_severity {
        findings.retain(|f| f.severity >= min);
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
    });

    let target = cli.path.display().to_string();

    if cli.sarif {
        println!("{}", output::sarif::render(&target, &findings));
    } else if cli.json {
        println!("{}", output::json::render(&target, &findings));
    } else {
        print!("{}", output::terminal::render(&target, &findings));
    }

    if cli.fail_on_findings && !findings.is_empty() {
        std::process::exit(1);
    }
}
