package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/binho13edu-coder/guardrail/pkg/scanner"
)

func TestWriteSARIF(t *testing.T) {
	var output bytes.Buffer
	findings := []scanner.Finding{{RuleName: "Public bucket", Description: "Bucket is public", Severity: "CRITICAL", FilePath: "infra/main.tf", LineNumber: 7}}
	if err := WriteSARIF(&output, findings); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if document["version"] != "2.1.0" {
		t.Fatalf("version = %v, want 2.1.0", document["version"])
	}
}
