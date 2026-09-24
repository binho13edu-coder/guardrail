package scanner

import (
	"fmt"
	"strings"
)

func MeetsThreshold(findings []Finding, threshold string) (bool, error) {
	threshold = strings.ToUpper(strings.TrimSpace(threshold))
	if threshold == "" || threshold == "NONE" {
		return false, nil
	}
	minimumSeverity, ok := severityRank(threshold)
	if !ok {
		return false, fmt.Errorf("invalid threshold %q: use critical, high, medium, low, or none", threshold)
	}
	for _, finding := range findings {
		rank, known := severityRank(finding.Severity)
		if known && rank >= minimumSeverity {
			return true, nil
		}
	}
	return false, nil
}

func severityRank(severity string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "LOW":
		return 1, true
	case "MEDIUM":
		return 2, true
	case "HIGH":
		return 3, true
	case "CRITICAL":
		return 4, true
	default:
		return 0, false
	}
}
