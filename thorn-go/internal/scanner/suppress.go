package scanner

import (
	"regexp"
	"strings"
)

const ignoreMarker = "thorn-ignore"

// isSuppressed checks whether a finding at line (1-indexed) for ruleID is
// suppressed by an inline "thorn-ignore" (suppresses every rule on that line) or
// "thorn-ignore:RULE_ID" (suppresses only that rule) marker on the same line.
func isSuppressed(content string, line int, ruleID string) bool {
	lines := strings.Split(content, "\n")
	if line < 1 || line > len(lines) {
		return false
	}
	lineText := lines[line-1]

	idx := strings.Index(lineText, ignoreMarker)
	if idx == -1 {
		return false
	}
	after := lineText[idx+len(ignoreMarker):]
	rest, hasColon := strings.CutPrefix(after, ":")
	if !hasColon {
		return true
	}
	end := 0
	for end < len(rest) && isAlphanumeric(rest[end]) {
		end++
	}
	return rest[:end] == ruleID
}

func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// parseIgnorePatterns parses .thornignore content into gitignore-style patterns
// (blank lines and # comments skipped).
func parseIgnorePatterns(content string) []string {
	var patterns []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, strings.TrimSuffix(line, "/"))
	}
	return patterns
}

var globSpecialChars = regexp.MustCompile(`[.+()\[\]{}^$|\\]`)

func globToRegex(pattern string) (*regexp.Regexp, error) {
	escaped := globSpecialChars.ReplaceAllStringFunc(pattern, func(s string) string {
		return "\\" + s
	})
	expanded := strings.ReplaceAll(escaped, "*", ".*")
	return regexp.Compile("(?i)^" + expanded + "$")
}

// isIgnored checks whether relPath (forward-slash relative path) is covered by
// any pattern — either as a whole-path glob match, or as a directory prefix (a
// pattern naming a directory ignores everything under it).
func isIgnored(patterns []string, relPath string) bool {
	for _, pattern := range patterns {
		if relPath == pattern || strings.HasPrefix(relPath, pattern+"/") {
			return true
		}
		if re, err := globToRegex(pattern); err == nil && re.MatchString(relPath) {
			return true
		}
	}
	return false
}
