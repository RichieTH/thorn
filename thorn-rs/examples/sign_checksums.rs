//! CI-only signing helper: reads THORN_DILITHIUM_PRIVATE_KEY (the real signing
//! seed, hex-encoded) from the environment and checksums.txt from stdin, writes
//! the raw ML-DSA-65 signature bytes to stdout.
//!
//! Not part of thorn's shipped scanner binaries -- this only runs in
//! release.yml, invoked as `cargo run --example sign_checksums`. The
//! corresponding *verification* logic (which thorn does ship, so downloaded
//! releases can be checked with `thorn verify-release`) lives in
//! src/verify_release.rs.

use std::io::{self, Read, Write};

use ml_dsa::{MlDsa65, SignatureEncoding, Signer, SigningKey};

fn main() {
    let seed_hex = std::env::var("THORN_DILITHIUM_PRIVATE_KEY")
        .unwrap_or_else(|_| fail("THORN_DILITHIUM_PRIVATE_KEY is not set"));

    let seed_bytes = decode_hex(&seed_hex).unwrap_or_else(|| {
        fail("THORN_DILITHIUM_PRIVATE_KEY is not valid hex");
    });
    let seed_array: [u8; 32] = seed_bytes
        .try_into()
        .unwrap_or_else(|_| fail("THORN_DILITHIUM_PRIVATE_KEY must decode to exactly 32 bytes"));

    let mut checksums = Vec::new();
    io::stdin()
        .read_to_end(&mut checksums)
        .unwrap_or_else(|e| fail(&format!("failed to read checksums from stdin: {e}")));

    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_array.into());
    let signature = signing_key.sign(&checksums);

    io::stdout()
        .write_all(signature.to_bytes().as_ref())
        .unwrap_or_else(|e| fail(&format!("failed to write signature to stdout: {e}")));
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn fail(msg: &str) -> ! {
    eprintln!("sign_checksums: {msg}");
    std::process::exit(1);
}
