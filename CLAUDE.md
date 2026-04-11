# Zelyo Operator — Project Guide for Claude

## What is this project?

Zelyo Operator is an open-source **Cloud-Native Application Protection Platform (CNAPP)** that runs as a Kubernetes operator. It detects security issues across Kubernetes workloads and AWS cloud accounts, correlates findings with an LLM, and auto-generates GitOps pull requests with fixes.

**Core identity:** Zelyo is a security product. Every code change must be evaluated through a security lens.

## Architecture

- **10 controllers** in `internal/controller/` orchestrate the Detect → Correlate → Fix pipeline
- **8 K8s scanners** in `internal/scanner/` check pods for security violations
- **48 cloud scanners** in `internal/cloudscanner/` (CSPM, CIEM, Network, DSPM, Supply Chain, CI/CD) scan AWS accounts
- **LLM reasoner** in `internal/remediation/` generates structured JSON fix plans
- **GitHub engine** in `internal/github/` opens PRs autonomously

## Key design constraints

1. **Read-only access** — Zelyo never mutates cluster state or cloud resources. All scanners use read-only APIs only.
2. **Non-destructive remediation** — fixes are always PRs, never direct changes. Human review required.
3. **63-char K8s name limit** — ScanReport names must use `GenerateName`, not `Name`.
4. **AWS per-region clients** — AWS SDK v2 clients are region-bound at creation. Use `NewClientsForRegion()` factory for multi-region scanning.

## Code conventions

- **Go 1.26**, **golangci-lint v2** with 30+ linters (gocyclo threshold: 15)
- Errors wrapped with `fmt.Errorf("context: %w", err)` — never bare `return err`
- Large structs passed by pointer (enforced by gocritic)
- All cloud scanner types implement `cloudscanner.CloudScanner` interface
- All K8s scanner types implement `scanner.Scanner` interface
- Rule type constants live in `api/v1alpha1/condition_types.go`
- Findings are always `scanner.Finding` — no custom finding structs

## Testing

- `make test` runs 15 packages
- Controllers use Ginkgo/Gomega with envtest
- Unit tests use standard `testing` package
- Cloud scanners should test pagination, empty results, and error paths

## What NOT to do

- Do not add AWS write permissions (no PutObject, DeleteBucket, etc.)
- Do not bypass golangci-lint checks with `//nolint` without justification
- Do not add external dependencies without strong justification
- Do not use `Name:` for ScanReport creation — always `GenerateName:`
- Do not log secrets, credentials, or API keys at any log level
