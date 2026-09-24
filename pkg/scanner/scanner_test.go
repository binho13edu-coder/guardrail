package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestScanPathFindsSecretsAndIgnoresDirectories(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "config.env"), "api_key=12345678901234567890123456789012\n")
	writeTestFile(t, filepath.Join(directory, "node_modules", "ignored.env"), "api_key=12345678901234567890123456789012\n")
	writeTestFile(t, filepath.Join(directory, ".git", "config"), "api_key=12345678901234567890123456789012\n")

	rules := []CompiledRule{{Rule: Rule{Name: "API key", Severity: "HIGH"}, Regex: mustCompile(t, `api_key=\w{32}`)}}
	findings, err := ScanPath(directory, rules)
	if err != nil {
		t.Fatalf("ScanPath() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ScanPath() returned %d findings, want 1", len(findings))
	}
	if findings[0].LineNumber != 1 || findings[0].FilePath != filepath.Join(directory, "config.env") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestLoadRulesRejectsInvalidSeverity(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeTestFile(t, path, "rules:\n  - name: sample\n    pattern: secret\n    severity: urgent\n")

	if _, err := LoadRules(path); err == nil {
		t.Fatal("LoadRules() error = nil, want validation error")
	}
}

func TestScanPathRunsIaCAnalyzers(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "Dockerfile"), "FROM node:latest\nUSER root\nADD https://example.com/app.tar.gz /app/\n")
	writeTestFile(t, filepath.Join(directory, "main.tf"), "resource \"aws_ebs_volume\" \"data\" {\n  size = 20\n}\nresource \"aws_s3_bucket\" \"public\" {\n  acl = \"public-read\"\n}\n")

	rules := []CompiledRule{
		{Rule: Rule{Name: "root", Pattern: "docker.user-root", Type: TypeConfig, Severity: "HIGH", TargetFiles: []string{"Dockerfile"}}},
		{Rule: Rule{Name: "tag", Pattern: "docker.mutable-tag", Type: TypeConfig, Severity: "MEDIUM", TargetFiles: []string{"Dockerfile"}}},
		{Rule: Rule{Name: "add", Pattern: "docker.add", Type: TypeConfig, Severity: "MEDIUM", TargetFiles: []string{"Dockerfile"}}},
		{Rule: Rule{Name: "public", Pattern: "terraform.public-access", Type: TypeConfig, Severity: "CRITICAL", TargetFiles: []string{"*.tf"}}},
		{Rule: Rule{Name: "encrypted", Pattern: "terraform.volume-encryption", Type: TypeConfig, Severity: "HIGH", TargetFiles: []string{"*.tf"}}},
	}

	findings, err := ScanPath(directory, rules)
	if err != nil {
		t.Fatalf("ScanPath() error = %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("ScanPath() returned %d findings, want 5: %+v", len(findings), findings)
	}
}

func TestMeetsThreshold(t *testing.T) {
	t.Parallel()
	findings := []Finding{{Severity: "HIGH"}}

	failed, err := MeetsThreshold(findings, "high")
	if err != nil || !failed {
		t.Fatalf("MeetsThreshold(high) = (%t, %v), want (true, nil)", failed, err)
	}
	failed, err = MeetsThreshold(findings, "critical")
	if err != nil || failed {
		t.Fatalf("MeetsThreshold(critical) = (%t, %v), want (false, nil)", failed, err)
	}
	if _, err := MeetsThreshold(findings, "urgent"); err == nil {
		t.Fatal("MeetsThreshold(urgent) error = nil, want validation error")
	}
}

func TestScanPathParsesJSONAndYAML(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "config.json"), `{"service":{"allow_public_access":true}}`)
	writeTestFile(t, filepath.Join(directory, "config.yaml"), "service:\n  publicly_accessible: true\n")

	rules := []CompiledRule{{Rule: Rule{Name: "public", Pattern: "config.boolean-true", Type: TypeConfig, Severity: "HIGH", TargetFiles: []string{"*.json", "*.yaml"}, MatchKeys: []string{"allow_public_access", "publicly_accessible"}}}}
	findings, err := ScanPath(directory, rules)
	if err != nil {
		t.Fatalf("ScanPath() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("ScanPath() returned %d findings, want 2: %+v", len(findings), findings)
	}
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return re
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
