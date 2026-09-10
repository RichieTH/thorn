// Command thorn is a security-hardened repo scanner: it detects hardcoded secrets,
// committed .env files, and common misconfigurations.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/RichieTH/thorn/thorn-go/internal/output"
	"github.com/RichieTH/thorn/thorn-go/internal/rules"
	"github.com/RichieTH/thorn/thorn-go/internal/scanner"
)

var (
	jsonOutput      bool
	minSeverityFlag string
)

func main() {
	rootCmd := &cobra.Command{
		Use:          "thorn [path]",
		Short:        "Security-hardened repo scanner for secrets, .env files, and misconfigs",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE:         run,
	}
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON instead of colored terminal output")
	rootCmd.Flags().StringVar(&minSeverityFlag, "min-severity", "", "only report findings at or above this severity (CRITICAL, HIGH, MEDIUM, INFO)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "thorn: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) == 1 {
		target = args[0]
	}

	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("path not found: %s", target)
	}

	findings, err := scanner.Scan(target, rules.All())
	if err != nil {
		return err
	}

	if minSeverityFlag != "" {
		min, err := rules.ParseSeverity(minSeverityFlag)
		if err != nil {
			return err
		}
		findings = filterMinSeverity(findings, min)
	}

	sortFindings(findings)

	if jsonOutput {
		out, err := output.RenderJSON(target, findings)
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	}

	fmt.Print(output.RenderTerminal(target, findings))
	return nil
}

func filterMinSeverity(findings []rules.Finding, min rules.Severity) []rules.Finding {
	kept := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity >= min {
			kept = append(kept, f)
		}
	}
	return kept
}

func sortFindings(findings []rules.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].File < findings[j].File
	})
}
