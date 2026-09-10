package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RichieTH/thorn/thorn-go/internal/rules"
)

func findingRuleIDsForFile(findings []rules.Finding, fileSuffix string) map[string]bool {
	ids := make(map[string]bool)
	for _, f := range findings {
		if strings.HasSuffix(filepath.ToSlash(f.File), fileSuffix) {
			ids[f.RuleID] = true
		}
	}
	return ids
}

func TestScanFixturesFindsEveryExpectedRule(t *testing.T) {
	// go test's working directory is this package's own directory
	// (internal/scanner), so three levels up reaches thorn/, the shared
	// fixtures/ root — unlike a crate-root-relative Cargo integration test.
	findings, err := Scan("../../../fixtures", rules.All())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	expected := map[string][]string{
		"fixtures/secrets/aws_keys.py":       {"SEC001", "SEC002"},
		"fixtures/secrets/api_keys.js":       {"SEC003", "SEC004"},
		"fixtures/secrets/github_token.yaml": {"SEC006"},
		"fixtures/secrets/private_key.txt":   {"SEC005"},
		"fixtures/dotenv/.env":               {"ENV001"},
		"fixtures/dotenv/.env.production":    {"ENV002"},
		"fixtures/misconfigs/Dockerfile":     {"CFG001"},
		"fixtures/misconfigs/settings.py":    {"CFG002", "CFG003"},
	}

	for fileSuffix, ruleIDs := range expected {
		found := findingRuleIDsForFile(findings, fileSuffix)
		for _, ruleID := range ruleIDs {
			if !found[ruleID] {
				t.Errorf("expected %s to be found in %s, but only found %v", ruleID, fileSuffix, found)
			}
		}
	}
}

func TestScanCleanDirectoryProducesNoFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("nothing interesting here\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture file: %v", err)
	}

	findings, err := Scan(dir, rules.All())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in a clean directory, got %d", len(findings))
	}
}

func TestScanSeededSecretIsFound(t *testing.T) {
	dir := t.TempDir()
	content := []byte("AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n")
	if err := os.WriteFile(filepath.Join(dir, "creds.py"), content, 0o644); err != nil {
		t.Fatalf("failed to write fixture file: %v", err)
	}

	findings, err := Scan(dir, rules.All())
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "SEC001" {
			found = true
		}
	}
	if !found {
		t.Error("expected SEC001 finding, got none")
	}
}
