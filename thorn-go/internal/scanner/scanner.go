// Package scanner walks a directory tree and runs every rule against every file in it.
package scanner

import (
	"os"
	"path/filepath"

	"github.com/RichieTH/thorn/thorn-go/internal/rules"
)

func relPathString(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	return filepath.ToSlash(rel)
}

// Scan walks root recursively and runs every rule in allRules against every file
// found, returning all findings.
//
// Two suppression mechanisms are honored automatically (no flag needed): a
// .thornignore file at root (gitignore-style patterns, skips whole files), and an
// inline "thorn-ignore" / "thorn-ignore:RULE_ID" comment on the matched line itself.
func Scan(root string, allRules []rules.Rule) ([]rules.Finding, error) {
	var ignorePatterns []string
	if data, err := os.ReadFile(filepath.Join(root, ".thornignore")); err == nil {
		ignorePatterns = parseIgnorePatterns(string(data))
	}

	files, err := walkFiles(root)
	if err != nil {
		return nil, err
	}

	var findings []rules.Finding
	for _, f := range files {
		if isIgnored(ignorePatterns, relPathString(root, f.Path)) {
			continue
		}
		for _, rule := range allRules {
			for _, finding := range rule.Scan(f.Path, f.Content) {
				if !isSuppressed(f.Content, finding.Line, finding.RuleID) {
					findings = append(findings, finding)
				}
			}
		}
	}
	return findings, nil
}
