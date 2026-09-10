// Package license provides offline license-key verification, gating only the
// --fail-on-findings exit-code behavior (v0.2). Because thorn's source is public,
// a plain shared-secret hash check can't actually be secure — anyone could read
// the secret out of the repo and mint their own "valid" key. Asymmetric signing
// (Ed25519) is the mechanism that stays offline-verifiable while keeping the
// *verification* key public: this package only ever needs the public key,
// embedded below. The private signing key that mints real keys lives outside
// this repo entirely.
//
// Key format: base64url(payload_json) "." base64url(signature_over_payload_bytes).
// payload_json is {"customer":"<string>","iat":<unix_ts>} -- v1 keys don't
// expire; that's a deliberate, documented simplification (see docs/development.md).
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

var publicKey = ed25519.PublicKey{
	0x72, 0xd0, 0xd5, 0x7a, 0x42, 0xfa, 0x4f, 0xc9, 0x97, 0xc7, 0x02, 0xcf, 0xd2, 0x18, 0xf5, 0xff,
	0xa0, 0x03, 0x0d, 0xe2, 0x8c, 0x8f, 0x39, 0x62, 0xe0, 0xe7, 0x31, 0xdf, 0xd7, 0x48, 0xd2, 0x0e,
}

// IsValid verifies that key is a well-formed license key signed by the embedded
// public key. Returns true only for a structurally valid, correctly signed key --
// never panics on malformed input.
func IsValid(key string) bool {
	payloadB64, sigB64, found := strings.Cut(key, ".")
	if !found {
		return false
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(publicKey, payload, sig)
}
