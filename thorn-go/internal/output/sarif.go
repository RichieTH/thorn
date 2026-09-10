package output

import (
	"encoding/json"

	"github.com/RichieTH/thorn/thorn-go/internal/rules"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	Rules   []sarifRuleDesc `json:"rules"`
}

type sarifRuleDesc struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifShortDesc `json:"shortDescription"`
}

type sarifShortDesc struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifLevel maps thorn's severity to SARIF's level: CRITICAL/HIGH -> error,
// MEDIUM -> warning, INFO -> note.
func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	default:
		return "note"
	}
}

// RenderSARIF renders findings as a SARIF 2.1.0 log, for upload to GitHub code
// scanning (github/codeql-action/upload-sarif) or any other SARIF-consuming tool.
func RenderSARIF(_ string, findings []rules.Finding) (string, error) {
	ruleOrder := make([]string, 0)
	ruleDescs := make(map[string]sarifRuleDesc)
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		if _, seen := ruleDescs[f.RuleID]; !seen {
			ruleDescs[f.RuleID] = sarifRuleDesc{
				ID:               f.RuleID,
				Name:             f.RuleName,
				ShortDescription: sarifShortDesc{Text: f.RuleName},
			}
			ruleOrder = append(ruleOrder, f.RuleID)
		}

		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.RuleName},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region:           sarifRegion{StartLine: f.Line},
				},
			}},
		})
	}

	sarifRules := make([]sarifRuleDesc, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		sarifRules = append(sarifRules, ruleDescs[id])
	}

	report := sarifReport{
		Version: "2.1.0",
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    "thorn",
				Version: Version,
				Rules:   sarifRules,
			}},
			Results: results,
		}},
	}

	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
