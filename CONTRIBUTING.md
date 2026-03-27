# 🤝 Contributing to Zelyo Operator

Thank you for your interest in contributing to Zelyo Operator! Whether you're fixing a bug, adding a feature, or improving documentation — every contribution makes Zelyo better for the community.

> **Quick links:** &nbsp;
> [GitHub Issues](https://github.com/zelyo-ai/zelyo-operator/issues) · [Discussions](https://github.com/zelyo-ai/zelyo-operator/discussions) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security Policy](SECURITY.md)

---

## 🗺️ Contribution Paths

| I want to... | Start here |
|---|---|
| 🐛 **Report a bug** | [Open an Issue](https://github.com/zelyo-ai/zelyo-operator/issues/new?template=bug_report.md) — include K8s version, operator version, and cloud provider |
| ✨ **Request a feature** | [Open an Issue](https://github.com/zelyo-ai/zelyo-operator/issues/new?template=feature_request.md) |
| 🔐 **Report a vulnerability** | Email **[security@zelyo.ai](mailto:security@zelyo.ai)** — **never** use public issues |
| 💻 **Submit code** | Fork → Branch → PR (see below) |
| 📖 **Improve docs** | Edit files in `docs/` and submit a PR |
| ❓ **Ask a question** | [Start a Discussion](https://github.com/zelyo-ai/zelyo-operator/discussions) |

---

## 💻 Pull Request Workflow

```
1. Fork the repo
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure CI passes  →  make lint test
5. Update docs if needed
6. Submit PR against `main`
```

### Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

| Types | Scopes |
|---|---|
| `feat`, `fix`, `docs`, `style`, `refactor` | `scanner`, `monitor`, `llm`, `remediation` |
| `perf`, `test`, `build`, `ci`, `chore` | `dashboard`, `notifier`, `helm`, `api`, `crd`, `ci` |

**Examples:**
```
feat(scanner): add RBAC over-permission detection
fix(llm): respect hourly token budget limits
docs(api): add OpenAPI spec for incidents endpoint
```

---

## 🛠️ Development Setup

### Prerequisites

- Go 1.24+
- Docker
- kubectl
- [kind](https://kind.sigs.k8s.io/) or [minikube](https://minikube.sigs.k8s.io/)
- [Kubebuilder](https://kubebuilder.io/) 4.x
- Helm 3.x

### Getting Started

```bash
# Clone your fork
git clone https://github.com/<your-username>/zelyo-operator.git
cd zelyo-operator

# Add upstream remote
git remote add upstream https://github.com/zelyo-ai/zelyo-operator.git

# Install dependencies
make install

# Generate manifests and code
make manifests generate

# Run tests
make test

# Run locally against a kind cluster
kind create cluster --name zelyo-operator-dev
make install  # Install CRDs
make run      # Run the operator
```

### Project Structure

```
├── api/v1alpha1/          # CRD type definitions
├── cmd/                   # Entrypoint
├── config/                # Kubebuilder kustomize configs
├── deploy/helm/           # Helm chart
├── docs/                  # Documentation
├── internal/
│   ├── controller/        # Kubebuilder controllers
│   ├── webhook/           # Admission webhooks
│   ├── llm/               # LLM client (BYO keys)
│   ├── scanner/           # Security scanner
│   ├── monitor/           # Real-time monitoring
│   ├── anomaly/           # Anomaly detection
│   ├── compliance/        # Compliance frameworks
│   ├── costoptimizer/     # Cost optimization
│   ├── drift/             # Config drift detection
│   ├── remediation/       # GitOps fix generator
│   ├── notifier/          # Alert routing
│   ├── dashboard/         # Embedded web UI
│   ├── api/               # REST API
│   └── ...
└── hack/                  # Development scripts
```

### Make Targets

| Target | Description |
|---|---|
| `make build` | Build the operator binary |
| `make test` | Run all tests |
| `make lint` | Run golangci-lint |
| `make manifests` | Generate CRD manifests |
| `make generate` | Generate deep copy methods |
| `make docker-build` | Build Docker image |
| `make install` | Install CRDs into cluster |
| `make run` | Run operator locally |

---

## 🧪 Testing

- **Unit tests**: Place in the same package as the code being tested
- **Integration tests**: Use envtest (Kubebuilder's test framework)
- **Coverage**: Aim for >80% coverage on new code

```bash
# Run all tests with coverage
make test

# Run specific package tests
go test ./internal/scanner/... -v
```

---

## ❓ Questions?

Open a [Discussion](https://github.com/zelyo-ai/zelyo-operator/discussions) for questions about the project.

---

<p align="center">
  Thank you for contributing to Zelyo Operator! 🎉
</p>
