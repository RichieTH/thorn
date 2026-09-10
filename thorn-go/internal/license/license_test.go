package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// testSigningKey is a throwaway test keypair — NOT the real signing key. Tests
// sign with this key's private half and verify against IsValid, which only ever
// checks against the real embedded public key — so these specifically test the
// shape/parsing logic, and one deliberately-mismatched-key test below proves
// IsValid actually rejects a signature from the wrong key.
func testSigningKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	return ed25519.NewKeyFromSeed(seed)
}

func signTestPayload(payload []byte) string {
	priv := testSigningKey()
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestKeySignedByWrongKeyIsRejected(t *testing.T) {
	key := signTestPayload([]byte(`{"customer":"test","iat":1}`))
	if IsValid(key) {
		t.Error("expected key signed by the wrong (test) key to be rejected")
	}
}

func TestTamperedPayloadIsRejected(t *testing.T) {
	key := signTestPayload([]byte(`{"customer":"test","iat":1}`))
	_, origSig, _ := strings.Cut(key, ".")

	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"customer":"evil","iat":1}`))
	tampered := tamperedPayload + "." + origSig
	if IsValid(tampered) {
		t.Error("expected tampered payload to be rejected")
	}
}

func TestMalformedKeyNoDotIsRejectedWithoutPanic(t *testing.T) {
	if IsValid("not-a-valid-key-at-all") {
		t.Error("expected malformed key to be rejected")
	}
}

func TestMalformedKeyBadBase64IsRejectedWithoutPanic(t *testing.T) {
	if IsValid("not!base64.also!not!base64") {
		t.Error("expected malformed key to be rejected")
	}
}

func TestMalformedKeyWrongSignatureLengthIsRejectedWithoutPanic(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString([]byte("payload")) + "." + base64.RawURLEncoding.EncodeToString([]byte("short"))
	if IsValid(key) {
		t.Error("expected wrong-length signature to be rejected")
	}
}

func TestEmptyStringIsRejected(t *testing.T) {
	if IsValid("") {
		t.Error("expected empty string to be rejected")
	}
}
