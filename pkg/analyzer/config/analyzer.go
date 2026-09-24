// Package config parses JSON and YAML configuration into data trees and evaluates policies.
package config

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Name        string
	Description string
	Pattern     string
	Severity    string
	MatchKeys   []string
}

type Finding struct {
	RuleName    string
	Description string
	Severity    string
	LineNumber  int
}

type Document struct {
	Data any
}

const BooleanTrue = "config.boolean-true"

func Parse(fileType string, content []byte, filePath string) (Document, error) {
	var data any
	var err error
	switch fileType {
	case "json":
		err = json.Unmarshal(content, &data)
	case "yaml":
		err = yaml.Unmarshal(content, &data)
	default:
		return Document{}, fmt.Errorf("parse config file %q: unsupported file type %q", filePath, fileType)
	}
	if err != nil {
		return Document{}, fmt.Errorf("parse %s file %q: %w", fileType, filePath, err)
	}
	return Document{Data: data}, nil
}

func Evaluate(document Document, rules []Rule) []Finding {
	var findings []Finding
	visit(document.Data, func(key string, value any) {
		for _, rule := range rules {
			if rule.Pattern != BooleanTrue || !matchesKey(key, rule.MatchKeys) {
				continue
			}
			isTrue, ok := value.(bool)
			if ok && isTrue {
				findings = append(findings, Finding{RuleName: rule.Name, Description: rule.Description, Severity: rule.Severity, LineNumber: 1})
			}
		}
	})
	return findings
}

func visit(value any, onValue func(key string, value any)) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			onValue(key, child)
			visit(child, onValue)
		}
	case []any:
		for _, child := range node {
			visit(child, onValue)
		}
	}
}

func matchesKey(key string, configuredKeys []string) bool {
	if len(configuredKeys) == 0 {
		return strings.Contains(strings.ToLower(key), "public")
	}
	for _, configuredKey := range configuredKeys {
		if strings.EqualFold(key, configuredKey) {
			return true
		}
	}
	return false
}
