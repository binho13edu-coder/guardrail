// Package reporter renders GuardRail findings for terminal users.
package reporter

import (
	"fmt"
	"io"

	"github.com/fatih/color"
	"github.com/binho13edu-coder/guardrail/pkg/scanner"
)

func PrintConsole(writer io.Writer, findings []scanner.Finding) error {
	if len(findings) == 0 {
		_, err := color.New(color.FgGreen).Fprintln(writer, "No security findings detected.")
		return err
	}

	for _, finding := range findings {
		severity := severityColor(finding.Severity).Sprint(finding.Severity)
		if _, err := fmt.Fprintf(writer, "[%s] %s:%d — %s (%s)\n", severity, finding.FilePath, finding.LineNumber, finding.RuleName, finding.Description); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "\n%d finding(s) detected.\n", len(findings))
	return err
}

func severityColor(severity string) *color.Color {
	switch severity {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold)
	case "HIGH":
		return color.New(color.FgRed)
	case "MEDIUM":
		return color.New(color.FgYellow)
	case "LOW":
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}
