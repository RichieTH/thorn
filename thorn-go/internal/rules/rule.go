// Package rules defines the Rule interface and the concrete SEC*/ENV*/CFG* rule
// implementations that scanner.Scan runs against every file in the target tree.
package rules

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity is ordered ascending so `>=` comparisons work for --min-severity.
type Severity int

const (
	Info Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Info:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// MarshalJSON renders the severity as its uppercase name, matching the schema in CLAUDE.md.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// ParseSeverity parses a case-insensitive severity name, e.g. for --min-severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return Critical, nil
	case "HIGH":
		return High, nil
	case "MEDIUM":
		return Medium, nil
	case "INFO":
		return Info, nil
	default:
		return Info, fmt.Errorf("unknown severity %q (want CRITICAL, HIGH, MEDIUM, or INFO)", s)
	}
}

// Finding is a single rule match. Match is always the literal string "REDACTED" —
// output is security-hardened by default and never echoes the actual secret text.
type Finding struct {
	Severity Severity `json:"severity"`
	RuleID   string   `json:"rule_id"`
	RuleName string   `json:"rule_name"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Match    string   `json:"match"`
}

// Rule scans a single file's content and reports zero or more findings.
type Rule interface {
	ID() string
	Name() string
	Severity() Severity
	Scan(path string, content string) []Finding
}

// findingAt builds a Finding for rule r at file:line, always with a redacted match.
func findingAt(r Rule, file string, line int) Finding {
	return Finding{
		Severity: r.Severity(),
		RuleID:   r.ID(),
		RuleName: r.Name(),
		File:     file,
		Line:     line,
		Match:    "REDACTED",
	}
}
