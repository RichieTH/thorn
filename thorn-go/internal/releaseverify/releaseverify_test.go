package releaseverify

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// testKeypair generates a throwaway test ML-DSA-65 keypair -- NOT the real
// signing key. Tests sign with this key and verify against a matching test
// *public* key (passed explicitly, bypassing the embedded real
// publicKeyBytes), proving the verification logic itself is correct without
// ever touching the real key.
func testKeypair(t *testing.T) (*mldsa65.PublicKey, *mldsa65.PrivateKey) {
	t.Helper()
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test keypair: %v", err)
	}
	return pk, sk
}

func verifyWithKey(pk *mldsa65.PublicKey, msg, sig []byte) bool {
	return mldsa65.Verify(pk, msg, nil, sig)
}

func TestValidSignatureIsAccepted(t *testing.T) {
	pk, sk := testKeypair(t)
	msg := []byte("checksums content")
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	if !verifyWithKey(pk, msg, sig) {
		t.Error("expected valid signature to be accepted")
	}
}

func TestTamperedChecksumsContentIsRejected(t *testing.T) {
	pk, sk := testKeypair(t)
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, []byte("checksums content"), nil, false, sig); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	if verifyWithKey(pk, []byte("tampered content"), sig) {
		t.Error("expected tampered content to be rejected")
	}
}

func TestSignatureFromWrongKeyIsRejected(t *testing.T) {
	_, skA := testKeypair(t)
	pkB, _ := testKeypair(t)
	msg := []byte("checksums content")
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(skA, msg, nil, false, sig); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	if verifyWithKey(pkB, msg, sig) {
		t.Error("expected signature from a different key to be rejected")
	}
}

func TestMalformedSignatureIsRejectedWithoutPanic(t *testing.T) {
	pk, _ := testKeypair(t)
	if verifyWithKey(pk, []byte("anything"), []byte("not-a-real-signature")) {
		t.Error("expected malformed signature to be rejected")
	}
}

func TestEmptySignatureIsRejectedWithoutPanic(t *testing.T) {
	pk, _ := testKeypair(t)
	if verifyWithKey(pk, []byte("anything"), []byte("")) {
		t.Error("expected empty signature to be rejected")
	}
}

func TestFindChecksumLocatesMatchingFilename(t *testing.T) {
	checksums := "abc123  file-a.tar.gz\ndef456  file-b.zip\n"
	if hash, ok := FindChecksum(checksums, "file-a.tar.gz"); !ok || hash != "abc123" {
		t.Errorf("expected abc123, got %q, ok=%v", hash, ok)
	}
	if hash, ok := FindChecksum(checksums, "file-b.zip"); !ok || hash != "def456" {
		t.Errorf("expected def456, got %q, ok=%v", hash, ok)
	}
}

func TestFindChecksumReturnsFalseForMissingFilename(t *testing.T) {
	checksums := "abc123  file-a.tar.gz\n"
	if _, ok := FindChecksum(checksums, "nonexistent.zip"); ok {
		t.Error("expected not found for missing filename")
	}
}
