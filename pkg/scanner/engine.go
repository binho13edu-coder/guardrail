package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	configanalyzer "github.com/binho13edu-coder/guardrail/pkg/analyzer/config"
	"github.com/binho13edu-coder/guardrail/pkg/analyzer/iac"
)

type FileType string

const (
	FileTypeText       FileType = "text"
	FileTypeDockerfile FileType = "dockerfile"
	FileTypeTerraform  FileType = "terraform"
	FileTypeJSON       FileType = "json"
	FileTypeYAML       FileType = "yaml"
)

const DefaultMaxParsedFileSize int64 = 10 * 1024 * 1024

var ErrFileTooLarge = fmt.Errorf("file exceeds the maximum parsed-file size")

// AnalysisContext is the artifact that travels through GuardRail's analysis pipeline.
// ParsedData contains a format-specific AST when the file type is supported.
type AnalysisContext struct {
	FilePath   string
	FileType   FileType
	Content    string
	ParsedData any
}

func BuildAnalysisContext(filePath string, maxParsedFileSize int64) (AnalysisContext, error) {
	context := AnalysisContext{FilePath: filePath, FileType: DiscoverFileType(filePath)}
	if context.FileType == FileTypeText {
		return context, nil
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return AnalysisContext{}, fmt.Errorf("inspect file %q: %w", filePath, err)
	}
	if maxParsedFileSize > 0 && info.Size() > maxParsedFileSize {
		return AnalysisContext{}, fmt.Errorf("%w: %q is %d bytes (limit %d bytes)", ErrFileTooLarge, filePath, info.Size(), maxParsedFileSize)
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return AnalysisContext{}, fmt.Errorf("read file %q: %w", filePath, err)
	}
	context.Content = string(content)

	parsedData, err := parseContent(context.FileType, content, filePath)
	if err != nil {
		return AnalysisContext{}, err
	}
	context.ParsedData = parsedData
	return context, nil
}

func parseContent(fileType FileType, content []byte, filePath string) (any, error) {
	switch fileType {
	case FileTypeDockerfile, FileTypeTerraform:
		return iac.Parse(string(fileType), content, filePath)
	case FileTypeJSON, FileTypeYAML:
		return configanalyzer.Parse(string(fileType), content, filePath)
	default:
		return nil, nil
	}
}

func DiscoverFileType(filePath string) FileType {
	fileName := filepath.Base(filePath)
	if strings.EqualFold(fileName, "Dockerfile") || strings.HasPrefix(strings.ToLower(fileName), "dockerfile.") {
		return FileTypeDockerfile
	}
	if strings.EqualFold(filepath.Ext(filePath), ".tf") {
		return FileTypeTerraform
	}
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".json":
		return FileTypeJSON
	case ".yaml", ".yml":
		return FileTypeYAML
	}
	return FileTypeText
}
