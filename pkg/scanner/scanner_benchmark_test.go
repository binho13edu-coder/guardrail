package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func BenchmarkScanPathRegexAndIaC(b *testing.B) {
	directory := b.TempDir()
	writeBenchmarkFile(b, filepath.Join(directory, "app.env"), "api_key=12345678901234567890123456789012\n")
	writeBenchmarkFile(b, filepath.Join(directory, "Dockerfile"), "FROM node:latest\nUSER root\n")
	writeBenchmarkFile(b, filepath.Join(directory, "main.tf"), "resource \"aws_ebs_volume\" \"data\" {\n  size = 20\n}\n")
	rules := []CompiledRule{
		{Rule: Rule{Name: "token", Type: TypeRegex, Severity: "HIGH"}, Regex: mustCompileBenchmark(b, `api_key=\w{32}`)},
		{Rule: Rule{Name: "root", Pattern: "docker.user-root", Type: TypeConfig, Severity: "HIGH", TargetFiles: []string{"Dockerfile"}}},
		{Rule: Rule{Name: "encryption", Pattern: "terraform.volume-encryption", Type: TypeConfig, Severity: "HIGH", TargetFiles: []string{"*.tf"}}},
	}

	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := ScanPath(directory, rules); err != nil {
			b.Fatal(err)
		}
	}
}

func mustCompileBenchmark(b *testing.B, pattern string) *regexp.Regexp {
	b.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		b.Fatal(err)
	}
	return re
}

func writeBenchmarkFile(b *testing.B, path, content string) {
	b.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		b.Fatal(err)
	}
}
