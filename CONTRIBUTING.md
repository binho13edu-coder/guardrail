# Contributing to GuardRail

1. Fork the repository and create a focused branch.
2. Add or update a rule under `rules/` and its tests under `pkg/`.
3. Run `go vet ./...`, `go test ./...`, and `go test -bench=. ./...` when changing scanner performance.
4. Keep each pull request scoped, explain the security impact, and include a safe fixture that proves the policy.

Never commit real credentials. Use synthetic values in tests and reports.
