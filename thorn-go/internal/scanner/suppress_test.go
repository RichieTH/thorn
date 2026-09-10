package scanner

import "testing"

func TestBareMarkerSuppressesAnyRule(t *testing.T) {
	line := `key = "x" # thorn-ignore`
	if !isSuppressed(line, 1, "SEC001") {
		t.Error("expected suppressed for SEC001")
	}
	if !isSuppressed(line, 1, "SEC099") {
		t.Error("expected suppressed for SEC099")
	}
}

func TestRuleSpecificMarkerSuppressesOnlyThatRule(t *testing.T) {
	line := `key = "x" # thorn-ignore:SEC001`
	if !isSuppressed(line, 1, "SEC001") {
		t.Error("expected SEC001 suppressed")
	}
	if isSuppressed(line, 1, "SEC002") {
		t.Error("expected SEC002 NOT suppressed")
	}
}

func TestNoMarkerIsNotSuppressed(t *testing.T) {
	if isSuppressed(`key = "x"`, 1, "SEC001") {
		t.Error("expected not suppressed")
	}
}

func TestOutOfRangeLineIsNotSuppressed(t *testing.T) {
	if isSuppressed("only one line", 5, "SEC001") {
		t.Error("expected not suppressed for out-of-range line")
	}
}

func TestParseIgnorePatternsSkipsBlanksAndComments(t *testing.T) {
	content := "# comment\n\nignored-dir/\n*.generated.py\n"
	patterns := parseIgnorePatterns(content)
	want := []string{"ignored-dir", "*.generated.py"}
	if len(patterns) != len(want) {
		t.Fatalf("expected %v, got %v", want, patterns)
	}
	for i := range want {
		if patterns[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, patterns)
		}
	}
}

func TestDirectoryPatternIgnoresEverythingUnderIt(t *testing.T) {
	patterns := []string{"ignored-dir"}
	if !isIgnored(patterns, "ignored-dir/leaked.py") {
		t.Error("expected ignored-dir/leaked.py to be ignored")
	}
	if isIgnored(patterns, "other-dir/leaked.py") {
		t.Error("expected other-dir/leaked.py to NOT be ignored")
	}
}

func TestGlobPatternMatchesWholePath(t *testing.T) {
	patterns := []string{"*.generated.py"}
	if !isIgnored(patterns, "model.generated.py") {
		t.Error("expected model.generated.py to be ignored")
	}
	if isIgnored(patterns, "model.py") {
		t.Error("expected model.py to NOT be ignored")
	}
}
