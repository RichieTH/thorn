mod license;
mod output;
mod rules;
mod scanner;
mod verify_release;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use rules::Severity;

/// Security-hardened repo scanner — detects hardcoded secrets, committed .env files,
/// and common misconfigurations.
#[derive(Parser)]
#[command(name = "thorn", version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

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

#[derive(Subcommand)]
enum Commands {
    /// Verify a downloaded release file against thorn's dual-signed checksums.txt
    /// (ML-DSA-65 / post-quantum signature, verified natively; the GPG signature
    /// on checksums.txt is verified separately via `gpg --verify`)
    VerifyRelease {
        /// The downloaded file to verify (e.g. thorn-rs-x86_64-unknown-linux-gnu.tar.gz)
        file: PathBuf,

        /// Path to the downloaded checksums.txt
        #[arg(long)]
        checksums: PathBuf,

        /// Path to the downloaded checksums.txt.dilithium signature
        #[arg(long)]
        signature: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::VerifyRelease {
            file,
            checksums,
            signature,
        }) => verify_release_command(&file, &checksums, &signature),
        None => scan_command(cli),
    }
}

fn scan_command(cli: Cli) {
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

fn verify_release_command(file: &PathBuf, checksums_path: &PathBuf, signature_path: &PathBuf) {
    let checksums_bytes = std::fs::read(checksums_path).unwrap_or_else(|e| {
        eprintln!("thorn: could not read {}: {e}", checksums_path.display());
        std::process::exit(2);
    });
    let signature_bytes = std::fs::read(signature_path).unwrap_or_else(|e| {
        eprintln!("thorn: could not read {}: {e}", signature_path.display());
        std::process::exit(2);
    });

    if !verify_release::verify_signature(&checksums_bytes, &signature_bytes) {
        eprintln!("thorn: checksums.txt signature is invalid — refusing to trust it");
        std::process::exit(1);
    }

    let checksums_text = String::from_utf8_lossy(&checksums_bytes);
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file.display().to_string());

    let Some(expected_hash) = verify_release::find_checksum(&checksums_text, &filename) else {
        eprintln!("thorn: {filename} is not listed in the (signature-verified) checksums.txt");
        std::process::exit(1);
    };

    let file_bytes = std::fs::read(file).unwrap_or_else(|e| {
        eprintln!("thorn: could not read {}: {e}", file.display());
        std::process::exit(2);
    });
    let actual_hash = sha256_hex(&file_bytes);

    if actual_hash != expected_hash {
        eprintln!(
            "thorn: checksum mismatch for {filename} — this file does not match the signed release"
        );
        std::process::exit(1);
    }

    println!("thorn: {filename} verified — checksum matches and checksums.txt signature is valid");
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
