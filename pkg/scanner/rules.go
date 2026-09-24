package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type RuleType string

const (
	TypeRegex  RuleType = "REGEX"
	TypeConfig RuleType = "CONFIG"
)

type Rule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Pattern     string   `yaml:"pattern"`
	Type        RuleType `yaml:"type"`
	Severity    string   `yaml:"severity"`
	TargetFiles []string `yaml:"target_files"`
	MatchKeys   []string `yaml:"match_keys"`
}

type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

type CompiledRule struct {
	Rule
	Regex *regexp.Regexp
}

func LoadRules(path string) ([]CompiledRule, error) {
	rulePaths, err := findRuleFiles(path)
	if err != nil {
		return nil, err
	}

	var compiledRules []CompiledRule
	for _, rulePath := range rulePaths {
		contents, err := os.ReadFile(rulePath)
		if err != nil {
			return nil, fmt.Errorf("read rules file %q: %w", rulePath, err)
		}

		var ruleSet RuleSet
		if err := yaml.Unmarshal(contents, &ruleSet); err != nil {
			return nil, fmt.Errorf("parse rules file %q: %w", rulePath, err)
		}
		for index, rule := range ruleSet.Rules {
			rule.Type = RuleType(strings.ToUpper(strings.TrimSpace(string(rule.Type))))
			if rule.Type == "" {
				rule.Type = TypeRegex
			}
			rule.Severity = strings.ToUpper(strings.TrimSpace(rule.Severity))
			if err := validateRule(rule); err != nil {
				return nil, fmt.Errorf("invalid rule in %q at index %d: %w", rulePath, index, err)
			}

			compiledRule := CompiledRule{Rule: rule}
			if rule.Type == TypeRegex {
				re, err := regexp.Compile(rule.Pattern)
				if err != nil {
					return nil, fmt.Errorf("compile rule %q: %w", rule.Name, err)
				}
				compiledRule.Regex = re
			}
			compiledRules = append(compiledRules, compiledRule)
		}
	}
	if len(compiledRules) == 0 {
		return nil, fmt.Errorf("rules path %q has no rules", path)
	}
	return compiledRules, nil
}

func findRuleFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("access rules path %q: %w", path, err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}

	var paths []string
	err = filepath.WalkDir(path, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		extension := strings.ToLower(filepath.Ext(filePath))
		if extension == ".yaml" || extension == ".yml" {
			paths = append(paths, filePath)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read rules directory %q: %w", path, err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("rules directory %q has no YAML files", path)
	}
	return paths, nil
}

func validateRule(rule Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("pattern is required")
	}
	switch rule.Type {
	case TypeRegex, TypeConfig:
	default:
		return fmt.Errorf("type %q must be REGEX or CONFIG", rule.Type)
	}
	if rule.Type == TypeConfig && len(rule.TargetFiles) == 0 {
		return fmt.Errorf("target_files is required for CONFIG rules")
	}
	switch rule.Severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return nil
	default:
		return fmt.Errorf("severity %q must be CRITICAL, HIGH, MEDIUM, or LOW", rule.Severity)
	}
}
