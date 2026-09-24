package reporter

import (
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/binho13edu-coder/guardrail/pkg/scanner"
)

const sarifVersion = "2.1.0"

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func WriteSARIF(writer io.Writer, findings []scanner.Finding) error {
	rules := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		rules[finding.RuleName] = sarifRule{ID: finding.RuleName, Name: finding.RuleName, ShortDescription: sarifMessage{Text: finding.Description}}
		results = append(results, sarifResult{RuleID: finding.RuleName, Level: sarifLevel(finding.Severity), Message: sarifMessage{Text: finding.Description}, Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(finding.FilePath)}, Region: sarifRegion{StartLine: finding.LineNumber}}}}})
	}

	ruleIDs := make([]string, 0, len(rules))
	for id := range rules {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	sarifRules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		sarifRules = append(sarifRules, rules[id])
	}

	log := sarifLog{Version: sarifVersion, Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "GuardRail", InformationURI: "https://github.com/binho13edu-coder/guardrail", Rules: sarifRules}}, Results: results}}}
	return json.NewEncoder(writer).Encode(log)
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}
