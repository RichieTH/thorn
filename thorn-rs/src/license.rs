//! Offline license-key verification, gating only the `--fail-on-findings` exit-code
//! behavior (v0.2). Because thorn's source is public, a plain shared-secret hash
//! check can't actually be secure — anyone could read the secret out of the repo
//! and mint their own "valid" key. Asymmetric signing (Ed25519) is the mechanism
//! that stays offline-verifiable while keeping the *verification* key public: this
//! module only ever needs the public key, embedded below. The private signing key
//! that mints real keys lives outside this repo entirely.
//!
//! Key format: `base64url(payload_json) "." base64url(signature_over_payload_bytes)`.
//! `payload_json` is `{"customer":"<string>","iat":<unix_ts>}` — v1 keys don't
//! expire; that's a deliberate, documented simplification (see docs/development.md).

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const PUBLIC_KEY_BYTES: [u8; 32] = [
    0x72, 0xd0, 0xd5, 0x7a, 0x42, 0xfa, 0x4f, 0xc9, 0x97, 0xc7, 0x02, 0xcf, 0xd2, 0x18, 0xf5, 0xff,
    0xa0, 0x03, 0x0d, 0xe2, 0x8c, 0x8f, 0x39, 0x62, 0xe0, 0xe7, 0x31, 0xdf, 0xd7, 0x48, 0xd2, 0x0e,
];

/// Verifies that `key` is a well-formed license key signed by the embedded public
/// key. Returns `true` only for a structurally valid, correctly signed key — never
/// panics on malformed input.
pub fn is_valid(key: &str) -> bool {
    let Some((payload_b64, sig_b64)) = key.split_once('.') else {
        return false;
    };

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let Ok(payload) = engine.decode(payload_b64) else {
        return false;
    };
    let Ok(sig_bytes) = engine.decode(sig_b64) else {
        return false;
    };
    let Ok(sig_array): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(&payload, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// A throwaway test keypair — NOT the real signing key. Tests sign with this
    /// key's private half and verify against `is_valid`, which only ever checks
    /// against the real embedded public key — so these specifically test the
    /// *shape*/parsing logic, and one deliberately-mismatched-key test below
    /// proves `is_valid` actually rejects a signature from the wrong key.
    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sign_test_payload(payload: &[u8]) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let signing_key = test_signing_key();
        let signature = signing_key.sign(payload);
        format!(
            "{}.{}",
            engine.encode(payload),
            engine.encode(signature.to_bytes())
        )
    }

    #[test]
    fn key_signed_by_wrong_key_is_rejected() {
        // Proves is_valid actually checks the signature, not just the shape --
        // this key is validly formed and signed, just by the wrong (test) key.
        let key = sign_test_payload(br#"{"customer":"test","iat":1}"#);
        assert!(!is_valid(&key));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = sign_test_payload(br#"{"customer":"test","iat":1}"#);
        let (_, sig) = key.split_once('.').unwrap();
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let tampered_payload = engine.encode(br#"{"customer":"evil","iat":1}"#);
        let tampered = format!("{tampered_payload}.{sig}");
        assert!(!is_valid(&tampered));
    }

    #[test]
    fn malformed_key_no_dot_is_rejected_without_panic() {
        assert!(!is_valid("not-a-valid-key-at-all"));
    }

    #[test]
    fn malformed_key_bad_base64_is_rejected_without_panic() {
        assert!(!is_valid("not!base64.also!not!base64"));
    }

    #[test]
    fn malformed_key_wrong_signature_length_is_rejected_without_panic() {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let key = format!("{}.{}", engine.encode(b"payload"), engine.encode(b"short"));
        assert!(!is_valid(&key));
    }

    #[test]
    fn empty_string_is_rejected() {
        assert!(!is_valid(""));
    }
}
