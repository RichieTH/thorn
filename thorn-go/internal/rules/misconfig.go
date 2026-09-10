package rules

import (
	"bufio"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	dockerUserRootPattern = regexp.MustCompile(`(?i)^\s*USER\s+root\b`)
	dockerUserAnyPattern  = regexp.MustCompile(`(?i)^\s*USER\s+\S+`)
	debugModePattern      = regexp.MustCompile(`(?i)\b(debug|flask_debug|debug_mode)\s*=\s*(true|1)\b`)
	localhostPattern      = regexp.MustCompile(`(?i)(127\.0\.0\.1|localhost)`)
)

type DockerfileUserRoot struct{}

func (DockerfileUserRoot) ID() string         { return "CFG001" }
func (DockerfileUserRoot) Name() string       { return "Dockerfile USER root" }
func (DockerfileUserRoot) Severity() Severity { return Medium }
func (r DockerfileUserRoot) Scan(path, content string) []Finding {
	if !strings.HasPrefix(filepath.Base(path), "Dockerfile") {
		return nil
	}

	file := relFile(path)
	var sawUser bool
	lineNum := 0
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if dockerUserRootPattern.MatchString(line) {
			return []Finding{findingAt(r, file, lineNum)}
		}
		if dockerUserAnyPattern.MatchString(line) {
			sawUser = true
		}
	}

	if !sawUser {
		lastLine := lineNum
		if lastLine == 0 {
			lastLine = 1
		}
		return []Finding{findingAt(r, file, lastLine)}
	}
	return nil
}

type DebugModeEnabled struct{}

func (DebugModeEnabled) ID() string         { return "CFG002" }
func (DebugModeEnabled) Name() string       { return "Debug mode enabled in config" }
func (DebugModeEnabled) Severity() Severity { return Medium }
func (r DebugModeEnabled) Scan(path, content string) []Finding {
	return scanLines(debugModePattern, r, relFile(path), content)
}

type HardcodedLocalhost struct{}

func (HardcodedLocalhost) ID() string         { return "CFG003" }
func (HardcodedLocalhost) Name() string       { return "Hardcoded localhost/127.0.0.1" }
func (HardcodedLocalhost) Severity() Severity { return Info }
func (r HardcodedLocalhost) Scan(path, content string) []Finding {
	return scanLines(localhostPattern, r, relFile(path), content)
}
