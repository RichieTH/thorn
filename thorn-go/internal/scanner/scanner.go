// Package scanner walks a directory tree and runs every rule against every file in it.
package scanner

import "github.com/RichieTH/thorn/thorn-go/internal/rules"

// Scan walks root recursively and runs every rule in allRules against every file found,
// returning all findings.
func Scan(root string, allRules []rules.Rule) ([]rules.Finding, error) {
	files, err := walkFiles(root)
	if err != nil {
		return nil, err
	}

	var findings []rules.Finding
	for _, f := range files {
		for _, rule := range allRules {
			findings = append(findings, rule.Scan(f.Path, f.Content)...)
		}
	}
	return findings, nil
}
