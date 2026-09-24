package scanner

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	configanalyzer "github.com/binho13edu-coder/guardrail/pkg/analyzer/config"
	"github.com/binho13edu-coder/guardrail/pkg/analyzer/iac"
	"go.uber.org/zap"
)

var ignoredDirectories = map[string]struct{}{
	".git":         {},
	".tools":       {},
	"node_modules": {},
}

type Finding struct {
	RuleName    string
	Description string
	Severity    string
	FilePath    string
	LineNumber  int
}

type ScanOptions struct {
	Logger            *zap.Logger
	MaxParsedFileSize int64
}

func ScanPath(path string, rules []CompiledRule) ([]Finding, error) {
	return ScanPathWithOptions(path, rules, ScanOptions{})
}

func ScanPathWithOptions(path string, rules []CompiledRule, options ScanOptions) ([]Finding, error) {
	if options.Logger == nil {
		options.Logger = zap.NewNop()
	}
	if options.MaxParsedFileSize == 0 {
		options.MaxParsedFileSize = DefaultMaxParsedFileSize
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("access scan path %q: %w", path, err)
	}
	if !info.IsDir() {
		return scanFileWithOptions(path, rules, options)
	}

	var findings []Finding
	err = filepath.WalkDir(path, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if _, ignored := ignoredDirectories[entry.Name()]; ignored {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}

		fileFindings, err := scanFileWithOptions(filePath, rules, options)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				options.Logger.Warn("skipping unreadable file", zap.String("file", filePath))
				return nil
			}
			return err
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan path %q: %w", path, err)
	}
	return findings, nil
}

func ScanFile(filePath string, rules []CompiledRule) ([]Finding, error) {
	return scanFileWithOptions(filePath, rules, ScanOptions{MaxParsedFileSize: DefaultMaxParsedFileSize})
}

func scanFileWithOptions(filePath string, rules []CompiledRule, options ScanOptions) ([]Finding, error) {
	context, err := BuildAnalysisContext(filePath, options.MaxParsedFileSize)
	if err != nil {
		if errors.Is(err, ErrFileTooLarge) {
			if options.Logger != nil {
				options.Logger.Warn("skipping structured parsing for oversized file", zap.String("file", filePath), zap.Error(err))
			}
			context = AnalysisContext{FilePath: filePath, FileType: DiscoverFileType(filePath)}
			return RunPipeline(context, rules)
		}
		return nil, err
	}
	return RunPipeline(context, rules)
}

// RunPipeline executes the policy stage over a discovered and parsed file context.
func RunPipeline(context AnalysisContext, rules []CompiledRule) ([]Finding, error) {
	findings, err := scanRegexPolicies(context, rules)
	if err != nil {
		return nil, err
	}
	configFindings, err := scanConfigPolicies(context, rules)
	if err != nil {
		return nil, err
	}
	return append(findings, configFindings...), nil
}

func scanRegexPolicies(context AnalysisContext, rules []CompiledRule) ([]Finding, error) {
	var findings []Finding
	file, err := os.Open(context.FilePath)
	if err != nil {
		return nil, fmt.Errorf("open file %q: %w", context.FilePath, err)
	}
	defer file.Close()
	lineScanner := bufio.NewScanner(file)
	lineScanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for lineNumber := 1; lineScanner.Scan(); lineNumber++ {
		line := lineScanner.Text()
		for _, rule := range rules {
			if (rule.Type != TypeRegex && rule.Type != "") || !matchesTargetFile(context.FilePath, rule.TargetFiles) {
				continue
			}
			if rule.Regex.MatchString(line) {
				findings = append(findings, Finding{
					RuleName:    rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					FilePath:    context.FilePath,
					LineNumber:  lineNumber,
				})
			}
		}
	}
	if err := lineScanner.Err(); err != nil {
		return nil, fmt.Errorf("read file %q: %w", context.FilePath, err)
	}
	return findings, nil
}

func scanConfigPolicies(context AnalysisContext, rules []CompiledRule) ([]Finding, error) {
	iacRules := make([]iac.Rule, 0)
	for _, rule := range rules {
		if rule.Type == TypeConfig && matchesTargetFile(context.FilePath, rule.TargetFiles) {
			iacRules = append(iacRules, iac.Rule{Name: rule.Name, Description: rule.Description, Pattern: rule.Pattern, Severity: rule.Severity})
		}
	}
	if len(iacRules) == 0 {
		return nil, nil
	}

	if context.ParsedData == nil {
		return nil, nil
	}
	results, err := evaluateConfigPolicies(context, iacRules, rules)
	if err != nil {
		return nil, err
	}
	findings := make([]Finding, 0, len(results))
	for _, result := range results {
		findings = append(findings, Finding{RuleName: result.RuleName, Description: result.Description, Severity: result.Severity, FilePath: context.FilePath, LineNumber: result.LineNumber})
	}
	return findings, nil
}

func evaluateConfigPolicies(context AnalysisContext, iacRules []iac.Rule, rules []CompiledRule) ([]iac.Finding, error) {
	switch context.FileType {
	case FileTypeDockerfile, FileTypeTerraform:
		return iac.Evaluate(string(context.FileType), context.ParsedData, iacRules)
	case FileTypeJSON, FileTypeYAML:
		document, ok := context.ParsedData.(configanalyzer.Document)
		if !ok {
			return nil, fmt.Errorf("evaluate %s policies: invalid parsed data", context.FileType)
		}
		configRules := make([]configanalyzer.Rule, 0)
		for _, rule := range rules {
			if rule.Type == TypeConfig && matchesTargetFile(context.FilePath, rule.TargetFiles) {
				configRules = append(configRules, configanalyzer.Rule{Name: rule.Name, Description: rule.Description, Pattern: rule.Pattern, Severity: rule.Severity, MatchKeys: rule.MatchKeys})
			}
		}
		configFindings := configanalyzer.Evaluate(document, configRules)
		findings := make([]iac.Finding, 0, len(configFindings))
		for _, finding := range configFindings {
			findings = append(findings, iac.Finding{RuleName: finding.RuleName, Description: finding.Description, Severity: finding.Severity, LineNumber: finding.LineNumber})
		}
		return findings, nil
	default:
		return nil, nil
	}
}

func matchesTargetFile(filePath string, targets []string) bool {
	if len(targets) == 0 {
		return true
	}
	fileName := filepath.Base(filePath)
	for _, target := range targets {
		matched, err := filepath.Match(target, fileName)
		if err == nil && matched {
			return true
		}
		if strings.EqualFold(target, fileName) {
			return true
		}
	}
	return false
}
