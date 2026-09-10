package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildThornBinary compiles cmd/thorn once per test into a temp dir and returns
// its path. os.Exit-based CLI behavior (exit codes, stderr messages) can only be
// verified by actually running the compiled binary as a subprocess -- calling
// run() in-process would kill the test binary itself on os.Exit.
func buildThornBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "thorn")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build thorn binary: %v\n%s", err, out)
	}
	return binPath
}

// These integration tests cover the "no key" / "invalid key" / "no
// --fail-on-findings" paths, which don't require a validly signed license key.
// The "valid key, gate actually opens" path is covered at the unit level in
// internal/license (signature verification against a test keypair) -- the real
// production signing key lives outside this repo entirely, so these tests can't
// mint a key thorn would actually accept.
func TestFailOnFindingsWithoutKeyExitsTwoWithMessage(t *testing.T) {
	bin := buildThornBinary(t)
	dir := t.TempDir()

	cmd := exec.Command(bin, "--fail-on-findings", dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected an ExitError, got %v (err type %T)", err, err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
	}
	if !strings.Contains(stderr.String(), "license key") {
		t.Errorf("expected license-required message in stderr, got: %s", stderr.String())
	}
}

func TestFailOnFindingsWithInvalidKeyExitsTwoWithMessage(t *testing.T) {
	bin := buildThornBinary(t)
	dir := t.TempDir()

	cmd := exec.Command(bin, "--fail-on-findings", "--license-key", "not-a-valid-key", dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected an ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
	}
	if !strings.Contains(stderr.String(), "license key") {
		t.Errorf("expected license-required message in stderr, got: %s", stderr.String())
	}
}

func TestWithoutFailOnFindingsExitsZeroRegardlessOfFindings(t *testing.T) {
	bin := buildThornBinary(t)
	dir := t.TempDir()
	content := []byte("AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n")
	if err := os.WriteFile(filepath.Join(dir, "creds.py"), content, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	cmd := exec.Command(bin, "--json", dir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("expected exit 0 without --fail-on-findings, got error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("expected valid JSON output: %v", err)
	}
	if parsed["summary"].(map[string]any)["total"].(float64) < 1 {
		t.Error("expected at least one finding in the seeded fixture")
	}
}

// verify-release: the real signing private key lives outside this repo
// (thorn-private-notes/, never committed and not available in CI test context),
// so these test the CLI wiring against non-privileged paths only. The full
// sign/verify round-trip against the real embedded public key is covered at the
// unit level in internal/releaseverify (via an explicit test keypair, bypassing
// the embedded key) and was manually verified end-to-end with the real key
// (including cross-language: Rust signs, Go verifies) during development -- see
// docs/development.md.

func TestVerifyReleaseWithMalformedSignatureExitsOne(t *testing.T) {
	bin := buildThornBinary(t)
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "downloaded.tar.gz")
	if err := os.WriteFile(targetFile, []byte("anything"), 0o644); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}
	checksums := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(checksums, []byte("abc  downloaded.tar.gz\n"), 0o644); err != nil {
		t.Fatalf("failed to write checksums: %v", err)
	}
	signature := filepath.Join(dir, "checksums.txt.dilithium")
	if err := os.WriteFile(signature, []byte("not-a-real-signature"), 0o644); err != nil {
		t.Fatalf("failed to write signature: %v", err)
	}

	cmd := exec.Command(bin, "verify-release", targetFile, "--checksums", checksums, "--signature", signature)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected an ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
	if !strings.Contains(stderr.String(), "signature is invalid") {
		t.Errorf("expected signature-invalid message in stderr, got: %s", stderr.String())
	}
}

func TestVerifyReleaseWithMissingChecksumsFileExitsTwo(t *testing.T) {
	bin := buildThornBinary(t)
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "downloaded.tar.gz")
	if err := os.WriteFile(targetFile, []byte("anything"), 0o644); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	cmd := exec.Command(
		bin, "verify-release", targetFile,
		"--checksums", filepath.Join(dir, "does-not-exist.txt"),
		"--signature", filepath.Join(dir, "does-not-exist.dilithium"),
	)
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected an ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2, got %d", exitErr.ExitCode())
	}
}

func TestVerifyReleaseDoesNotDisturbDefaultScanBehavior(t *testing.T) {
	bin := buildThornBinary(t)
	dir := t.TempDir()
	content := []byte("AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n")
	if err := os.WriteFile(filepath.Join(dir, "creds.py"), content, 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	cmd := exec.Command(bin, "--json", dir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("expected valid JSON output: %v", err)
	}
	if parsed["summary"].(map[string]any)["total"].(float64) < 1 {
		t.Error("expected at least one finding")
	}
}

// Sanity check that the ed25519 stdlib primitives thorn's license package relies
// on behave as expected on this platform/toolchain -- catches a broken Go
// toolchain install before it manifests as a confusing license-verification bug.
func TestEd25519StdlibSanityCheck(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	msg := []byte("sanity check")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("ed25519 sign/verify round-trip failed")
	}
}
