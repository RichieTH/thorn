package rules

import (
	"bufio"
	"path/filepath"
	"regexp"
	"strings"
)

// relFile normalizes a walked path to forward slashes, matching thorn-rs's output
// so both implementations produce an identical JSON schema regardless of OS.
func relFile(path string) string {
	return filepath.ToSlash(path)
}

// scanLines runs pattern against every line of content, producing one finding per
// matching line (1-indexed, matching editor/terminal conventions).
func scanLines(pattern *regexp.Regexp, r Rule, file string, content string) []Finding {
	var findings []Finding
	lineNum := 0
	scanner := bufio.NewScanner(strings.NewReader(content))
	// Lines longer than bufio's default 64KiB token size are simply skipped rather
	// than aborting the whole file's scan.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lineNum++
		if pattern.MatchString(scanner.Text()) {
			findings = append(findings, findingAt(r, file, lineNum))
		}
	}
	return findings
}
