// Command thorn is a security-hardened repo scanner: it detects hardcoded secrets,
// committed .env files, and common misconfigurations.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/RichieTH/thorn/thorn-go/internal/license"
	"github.com/RichieTH/thorn/thorn-go/internal/output"
	"github.com/RichieTH/thorn/thorn-go/internal/rules"
	"github.com/RichieTH/thorn/thorn-go/internal/scanner"
)

var (
	jsonOutput      bool
	sarifOutput     bool
	minSeverityFlag string
	failOnFindings  bool
	licenseKeyFlag  string
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
	rootCmd.Flags().BoolVar(&sarifOutput, "sarif", false, "emit a SARIF 2.1.0 log instead of colored terminal output")
	rootCmd.Flags().StringVar(&minSeverityFlag, "min-severity", "", "only report findings at or above this severity (CRITICAL, HIGH, MEDIUM, INFO)")
	rootCmd.Flags().BoolVar(&failOnFindings, "fail-on-findings", false, "exit with code 1 if any findings remain after filtering (paid feature — requires --license-key or THORN_LICENSE_KEY)")
	rootCmd.Flags().StringVar(&licenseKeyFlag, "license-key", "", "license key unlocking --fail-on-findings (falls back to THORN_LICENSE_KEY)")
	rootCmd.MarkFlagsMutuallyExclusive("json", "sarif")

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

	if failOnFindings {
		key := licenseKeyFlag
		if key == "" {
			key = os.Getenv("THORN_LICENSE_KEY")
		}
		if !license.IsValid(key) {
			fmt.Fprintln(os.Stderr, "thorn: --fail-on-findings requires a valid license key (set --license-key or THORN_LICENSE_KEY)")
			os.Exit(2)
		}
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

	switch {
	case sarifOutput:
		out, err := output.RenderSARIF(target, findings)
		if err != nil {
			return err
		}
		fmt.Println(out)
	case jsonOutput:
		out, err := output.RenderJSON(target, findings)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(output.RenderTerminal(target, findings))
	}

	if failOnFindings && len(findings) > 0 {
		os.Exit(1)
	}
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
