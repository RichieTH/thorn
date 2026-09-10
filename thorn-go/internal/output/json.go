package output

import (
	"encoding/json"
	"time"

	"github.com/RichieTH/thorn/thorn-go/internal/rules"
)

// Version is thorn's release version, embedded in the JSON report. Kept in lockstep
// with thorn-rs's Cargo.toml version so both implementations report identically.
const Version = "0.1.0"

type summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Info     int `json:"info"`
}

type report struct {
	Version   string          `json:"version"`
	ScannedAt string          `json:"scanned_at"`
	Target    string          `json:"target"`
	Findings  []rules.Finding `json:"findings"`
	Summary   summary         `json:"summary"`
}

func summarize(findings []rules.Finding) summary {
	s := summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case rules.Critical:
			s.Critical++
		case rules.High:
			s.High++
		case rules.Medium:
			s.Medium++
		case rules.Info:
			s.Info++
		}
	}
	return s
}

// RenderJSON builds the machine-readable report matching the schema in CLAUDE.md.
// findings is never nil in the output — an empty scan renders "findings": [].
func RenderJSON(target string, findings []rules.Finding) (string, error) {
	if findings == nil {
		findings = []rules.Finding{}
	}

	r := report{
		Version:   Version,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Target:    target,
		Findings:  findings,
		Summary:   summarize(findings),
	}

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
