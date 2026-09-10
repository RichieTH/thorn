package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/RichieTH/thorn/thorn-go/internal/rules"
)

func testFinding(ruleID, ruleName string, severity rules.Severity) rules.Finding {
	return rules.Finding{
		Severity: severity,
		RuleID:   ruleID,
		RuleName: ruleName,
		File:     "a.py",
		Line:     7,
		Match:    "REDACTED",
	}
}

func TestRenderSARIFWithCorrectShape(t *testing.T) {
	findings := []rules.Finding{testFinding("SEC001", "Hardcoded AWS Secret Key", rules.Critical)}
	out, err := RenderSARIF(".", findings)
	if err != nil {
		t.Fatalf("RenderSARIF returned error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %v", parsed["version"])
	}
	if parsed["$schema"] != sarifSchema {
		t.Errorf("expected schema %s, got %v", sarifSchema, parsed["$schema"])
	}

	runs := parsed["runs"].([]any)
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "thorn" {
		t.Errorf("expected driver name thorn, got %v", driver["name"])
	}

	results := run["results"].([]any)
	result := results[0].(map[string]any)
	if result["ruleId"] != "SEC001" {
		t.Errorf("expected ruleId SEC001, got %v", result["ruleId"])
	}
	if result["level"] != "error" {
		t.Errorf("expected level error, got %v", result["level"])
	}

	loc := result["locations"].([]any)[0].(map[string]any)
	physLoc := loc["physicalLocation"].(map[string]any)
	if physLoc["artifactLocation"].(map[string]any)["uri"] != "a.py" {
		t.Errorf("expected uri a.py, got %v", physLoc["artifactLocation"])
	}
	if physLoc["region"].(map[string]any)["startLine"] != float64(7) {
		t.Errorf("expected startLine 7, got %v", physLoc["region"])
	}
}

func TestSARIFSeverityLevelMapping(t *testing.T) {
	cases := []struct {
		severity rules.Severity
		want     string
	}{
		{rules.Critical, "error"},
		{rules.High, "error"},
		{rules.Medium, "warning"},
		{rules.Info, "note"},
	}
	for _, tc := range cases {
		if got := sarifLevel(tc.severity); got != tc.want {
			t.Errorf("sarifLevel(%v) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

func TestSARIFNeverLeaksMatchTextOnlyRuleName(t *testing.T) {
	findings := []rules.Finding{testFinding("SEC001", "Hardcoded AWS Secret Key", rules.Critical)}
	out, err := RenderSARIF(".", findings)
	if err != nil {
		t.Fatalf("RenderSARIF returned error: %v", err)
	}
	if strings.Contains(out, "AKIA") {
		t.Error("SARIF output must never contain matched secret text")
	}
	if !strings.Contains(out, "Hardcoded AWS Secret Key") {
		t.Error("expected rule name to be present")
	}
}

func TestSARIFEmptyFindingsProducesEmptyResultsAndRules(t *testing.T) {
	out, err := RenderSARIF(".", nil)
	if err != nil {
		t.Fatalf("RenderSARIF returned error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	run := parsed["runs"].([]any)[0].(map[string]any)
	if len(run["results"].([]any)) != 0 {
		t.Error("expected empty results")
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if len(driver["rules"].([]any)) != 0 {
		t.Error("expected empty rules")
	}
}

func TestSARIFDedupesRuleDescriptorsAcrossMultipleFindingsOfSameRule(t *testing.T) {
	findings := []rules.Finding{
		testFinding("SEC001", "Hardcoded AWS Secret Key", rules.Critical),
		testFinding("SEC001", "Hardcoded AWS Secret Key", rules.Critical),
	}
	out, err := RenderSARIF(".", findings)
	if err != nil {
		t.Fatalf("RenderSARIF returned error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	run := parsed["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if len(driver["rules"].([]any)) != 1 {
		t.Errorf("expected 1 deduped rule descriptor, got %d", len(driver["rules"].([]any)))
	}
	if len(run["results"].([]any)) != 2 {
		t.Errorf("expected 2 results, got %d", len(run["results"].([]any)))
	}
}
