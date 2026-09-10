package output

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/RichieTH/thorn/thorn-go/internal/rules"
)

func severityColor(s rules.Severity) *color.Color {
	switch s {
	case rules.Critical:
		return color.New(color.FgRed, color.Bold)
	case rules.High:
		return color.New(color.FgMagenta, color.Bold)
	case rules.Medium:
		return color.New(color.FgYellow, color.Bold)
	default:
		return color.New(color.FgCyan, color.Bold)
	}
}

// RenderTerminal builds the human-readable, colored report for interactive use.
func RenderTerminal(target string, findings []rules.Finding) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Scanning %s\n\n", target)

	if len(findings) == 0 {
		fmt.Fprintln(&out, color.GreenString("No findings — clean scan."))
		return out.String()
	}

	for _, f := range findings {
		label := severityColor(f.Severity).Sprint(f.Severity.String())
		fmt.Fprintf(&out, "[%s] %s — %s:%d (%s)\n", label, f.RuleName, f.File, f.Line, f.RuleID)
	}

	s := summarize(findings)
	fmt.Fprintf(&out, "\n%d findings: %s critical, %s high, %s medium, %s info\n",
		s.Total,
		color.RedString("%d", s.Critical),
		color.MagentaString("%d", s.High),
		color.YellowString("%d", s.Medium),
		color.CyanString("%d", s.Info),
	)

	return out.String()
}
