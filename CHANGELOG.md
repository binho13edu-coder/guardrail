# Changelog

All notable changes to GuardRail are documented here.

## [0.1.0] - 2026-09-24

### Added

- Cobra-based `guardrail scan <path>` CLI with CI thresholds and exit codes.
- YAML rule engine for secret detection and structured configuration policies.
- Semantic Dockerfile checks and HCL AST parsing for Terraform policies.
- JSON/YAML structured public-access checks.
- Structured console/JSON logging, memory safeguards, tests, benchmark, and GitHub Actions CI.
- SARIF 2.1.0 output and a Code Scanning upload workflow.
- Reusable GitHub Action inputs for severity thresholds and custom rule paths.
