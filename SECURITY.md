# 🔐 Security Policy

## Reporting a Vulnerability

The Zelyo Operator team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

> **⚠️ Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

Send an email to **[security@zelyo.ai](mailto:security@zelyo.ai)** with:

- **Description** of the vulnerability
- **Steps to reproduce** (proof of concept if possible)
- **Impact assessment** — what an attacker could achieve
- **Affected versions** (if known)

### Response Timeline

```
📩 Report received
 └─ ⏳ Acknowledgment .............. within 48 hours
     └─ 🔍 Initial assessment ...... within 5 business days
         └─ 📅 Fix timeline ........ within 10 business days
             └─ 📢 Advisory ........ upon fix release
```

### Scope

**In scope:**

| Component | Examples |
|---|---|
| Operator binary & images | Container vulnerabilities, binary exploits |
| Helm chart & manifests | Misconfigurations, privilege escalation |
| CRD validation & webhooks | Bypass, injection, denial of service |
| LLM integration | API key leakage, prompt injection |
| REST API & Dashboard | Authentication bypass, XSS, CSRF |

**Out of scope:**

- Third-party dependencies (report upstream, but please let us know)
- Issues in Kubernetes itself
- Social engineering attacks

---

## Supported Versions

| Version | Supported |
|:---:|:---:|
| Latest release | ✅ Full support |
| Previous minor | ✅ Security fixes only |
| Older versions | ❌ Not supported |

---

## 🛡️ Security Best Practices

When deploying Zelyo Operator, follow these hardening guidelines:

1. **Store API keys in Kubernetes Secrets** — never in ConfigMaps or environment variables directly
2. **Use network policies** to restrict Zelyo Operator's egress to only required endpoints
3. **Enable RBAC** — Zelyo Operator uses read-only cluster access by design
4. **Verify image signatures** using [Cosign](docs/supply-chain-security.md) before deployment
5. **Review SBOMs** attached to each release for supply chain transparency
6. **Enable audit logging** on your cluster to track Zelyo Operator's API calls

---

## 🏆 Hall of Fame

We gratefully acknowledge security researchers who help keep Zelyo Operator and its users safe. With your permission, we will acknowledge your contribution in our security advisories.

> *No vulnerabilities reported yet — be the first responsible discloser!*
