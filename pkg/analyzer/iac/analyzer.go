// Package iac parses IaC formats and evaluates semantic configuration policies.
package iac

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

type Rule struct {
	Name        string
	Description string
	Pattern     string
	Severity    string
}

type Finding struct {
	RuleName    string
	Description string
	Severity    string
	LineNumber  int
}

type DockerInstruction struct {
	Command    string
	Arguments  string
	LineNumber int
}

type DockerfileDocument struct {
	Instructions []DockerInstruction
}

type TerraformDocument struct {
	Body *hclsyntax.Body
}

const (
	dockerUserRoot      = "docker.user-root"
	dockerMutableTag    = "docker.mutable-tag"
	dockerAdd           = "docker.add"
	terraformPublic     = "terraform.public-access"
	terraformEncryption = "terraform.volume-encryption"
)

func Parse(fileType string, content []byte, filePath string) (any, error) {
	switch fileType {
	case "dockerfile":
		return parseDockerfile(string(content)), nil
	case "terraform":
		parser := hclparse.NewParser()
		file, diagnostics := parser.ParseHCL(content, filePath)
		if diagnostics.HasErrors() {
			return nil, fmt.Errorf("parse Terraform file %q: %s", filePath, diagnostics.Error())
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			return nil, fmt.Errorf("parse Terraform file %q: unsupported body", filePath)
		}
		return TerraformDocument{Body: body}, nil
	default:
		return nil, nil
	}
}

func Evaluate(fileType string, parsedData any, rules []Rule) ([]Finding, error) {
	switch fileType {
	case "dockerfile":
		document, ok := parsedData.(DockerfileDocument)
		if !ok {
			return nil, fmt.Errorf("evaluate Dockerfile policies: invalid AST")
		}
		return evaluateDockerfile(document, rules), nil
	case "terraform":
		document, ok := parsedData.(TerraformDocument)
		if !ok {
			return nil, fmt.Errorf("evaluate Terraform policies: invalid AST")
		}
		return evaluateTerraform(document, rules), nil
	default:
		return nil, nil
	}
}

func parseDockerfile(content string) DockerfileDocument {
	var document DockerfileDocument
	var current string
	startLine := 0
	for index, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if current == "" {
			startLine = index + 1
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		continued := strings.HasSuffix(line, "\\")
		line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		current = strings.TrimSpace(current + " " + line)
		if continued {
			continue
		}

		parts := strings.Fields(current)
		if len(parts) > 0 {
			command := strings.ToUpper(parts[0])
			arguments := strings.TrimSpace(strings.TrimPrefix(current, parts[0]))
			document.Instructions = append(document.Instructions, DockerInstruction{Command: command, Arguments: arguments, LineNumber: startLine})
		}
		current = ""
	}
	return document
}

func evaluateDockerfile(document DockerfileDocument, rules []Rule) []Finding {
	var findings []Finding
	for _, instruction := range document.Instructions {
		for _, rule := range rules {
			matched := false
			switch rule.Pattern {
			case dockerUserRoot:
				user := strings.Fields(instruction.Arguments)
				matched = instruction.Command == "USER" && len(user) > 0 && (strings.EqualFold(user[0], "root") || user[0] == "0")
			case dockerMutableTag:
				image := strings.Fields(instruction.Arguments)
				matched = instruction.Command == "FROM" && len(image) > 0 && mutableImageReference(image[0])
			case dockerAdd:
				matched = instruction.Command == "ADD"
			}
			if matched {
				findings = append(findings, findingFromRule(rule, instruction.LineNumber))
			}
		}
	}
	return findings
}

func evaluateTerraform(document TerraformDocument, rules []Rule) []Finding {
	var findings []Finding
	for _, block := range document.Body.Blocks {
		if block.Type != "resource" || len(block.Labels) == 0 {
			continue
		}
		resourceType := block.Labels[0]
		for _, rule := range rules {
			switch rule.Pattern {
			case terraformPublic:
				if resourceHasPublicAccess(resourceType, block.Body.Attributes) {
					findings = append(findings, findingFromRule(rule, block.TypeRange.Start.Line))
				}
			case terraformEncryption:
				if resourceType == "aws_ebs_volume" && !attributeIsTrue(block.Body.Attributes, "encrypted") {
					findings = append(findings, findingFromRule(rule, block.TypeRange.Start.Line))
				}
			}
		}
	}
	return findings
}

func resourceHasPublicAccess(resourceType string, attributes hclsyntax.Attributes) bool {
	if attributeIsTrue(attributes, "public_access") {
		return true
	}
	if resourceType == "aws_s3_bucket" {
		return attributeEquals(attributes, "acl", "public-read") || attributeEquals(attributes, "acl", "public-read-write")
	}
	if resourceType == "aws_s3_bucket_public_access_block" {
		return attributeIsFalse(attributes, "block_public_acls") || attributeIsFalse(attributes, "block_public_policy") || attributeIsFalse(attributes, "restrict_public_buckets")
	}
	return false
}

func attributeIsTrue(attributes hclsyntax.Attributes, name string) bool {
	return attributeBoolean(attributes, name, true)
}

func attributeIsFalse(attributes hclsyntax.Attributes, name string) bool {
	return attributeBoolean(attributes, name, false)
}

func attributeBoolean(attributes hclsyntax.Attributes, name string, expected bool) bool {
	attribute, exists := attributes[name]
	if !exists {
		return false
	}
	value, diagnostics := attribute.Expr.Value(nil)
	return !diagnostics.HasErrors() && value.IsKnown() && !value.IsNull() && value.Type() == cty.Bool && value.True() == expected
}

func attributeEquals(attributes hclsyntax.Attributes, name, expected string) bool {
	attribute, exists := attributes[name]
	if !exists {
		return false
	}
	value, diagnostics := attribute.Expr.Value(nil)
	return !diagnostics.HasErrors() && value.IsKnown() && !value.IsNull() && value.Type() == cty.String && value.AsString() == expected
}

func mutableImageReference(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	lastSlash := strings.LastIndex(image, "/")
	return !strings.Contains(image[lastSlash+1:], ":") || strings.HasSuffix(strings.ToLower(image), ":latest")
}

func findingFromRule(rule Rule, lineNumber int) Finding {
	return Finding{RuleName: rule.Name, Description: rule.Description, Severity: rule.Severity, LineNumber: lineNumber}
}
