package output

import (
	"encoding/json"
	"testing"

	"github.com/RichieTH/thorn/thorn-go/internal/rules"
)

func TestRenderJSONWithFindings(t *testing.T) {
	findings := []rules.Finding{{
		Severity: rules.Critical,
		RuleID:   "SEC001",
		RuleName: "Hardcoded AWS Secret Key",
		File:     "a.py",
		Line:     1,
		Match:    "REDACTED",
	}}

	out, err := RenderJSON(".", findings)
	if err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	summary := parsed["summary"].(map[string]any)
	if summary["total"].(float64) != 1 {
		t.Errorf("expected total=1, got %v", summary["total"])
	}
	if summary["critical"].(float64) != 1 {
		t.Errorf("expected critical=1, got %v", summary["critical"])
	}

	foundList := parsed["findings"].([]any)
	first := foundList[0].(map[string]any)
	if first["rule_id"] != "SEC001" {
		t.Errorf("expected rule_id SEC001, got %v", first["rule_id"])
	}
	if first["match"] != "REDACTED" {
		t.Errorf("expected match REDACTED, got %v", first["match"])
	}
}

func TestRenderJSONWithNoFindings(t *testing.T) {
	out, err := RenderJSON(".", nil)
	if err != nil {
		t.Fatalf("RenderJSON returned error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	summary := parsed["summary"].(map[string]any)
	if summary["total"].(float64) != 0 {
		t.Errorf("expected total=0, got %v", summary["total"])
	}
	findings := parsed["findings"].([]any)
	if len(findings) != 0 {
		t.Errorf("expected empty findings array, got %d entries", len(findings))
	}
}
