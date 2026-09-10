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

    /// Only report findings at or above this severity
    #[arg(long, value_enum)]
    min_severity: Option<Severity>,
}

fn main() {
    let cli = Cli::parse();

    if !cli.path.exists() {
        eprintln!("thorn: path not found: {}", cli.path.display());
        std::process::exit(1);
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

    if cli.json {
        println!("{}", output::json::render(&target, &findings));
    } else {
        print!("{}", output::terminal::render(&target, &findings));
    }
}
