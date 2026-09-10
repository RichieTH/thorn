package rules

import "testing"

func TestDockerfileUserRoot(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		content string
		matches bool
	}{
		{"matches explicit USER root", "Dockerfile", "FROM ubuntu:22.04\nUSER root\nCMD [\"./server\"]", true},
		{"ignores non-root user", "Dockerfile", "FROM ubuntu:22.04\nUSER appuser\nCMD [\"./server\"]", false},
		{"flags missing USER directive", "Dockerfile", "FROM ubuntu:22.04\nCMD [\"./server\"]", true},
		{"ignores non-Dockerfile", "notes.txt", "USER root", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := DockerfileUserRoot{}.Scan(tc.path, tc.content)
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
		})
	}
}

func TestDebugModeEnabled(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		matches bool
	}{
		{"matches DEBUG = True", `DEBUG = True`, true},
		{"matches FLASK_DEBUG = 1", `FLASK_DEBUG = 1`, true},
		{"ignores unrelated setting", `LOG_LEVEL = "INFO"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := DebugModeEnabled{}.Scan("settings.py", tc.line)
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
		})
	}
}

func TestHardcodedLocalhost(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		matches bool
	}{
		{"matches 127.0.0.1", `DATABASE_HOST = "127.0.0.1"`, true},
		{"matches localhost", `REDIS_URL = "redis://localhost:6379"`, true},
		{"ignores unrelated setting", `MAX_CONNECTIONS = 100`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := HardcodedLocalhost{}.Scan("settings.py", tc.line)
			if got := len(findings); (tc.matches && got != 1) || (!tc.matches && got != 0) {
				t.Fatalf("matches=%v: got %d findings", tc.matches, got)
			}
		})
	}
}
