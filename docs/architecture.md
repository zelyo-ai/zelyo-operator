# Aotanami Architecture

## Overview

Aotanami is a Kubernetes Operator built with [Kubebuilder](https://kubebuilder.io/) and [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime). It runs as a single deployment in your cluster with **read-only access** to cluster resources, using **Agentic AI** (BYO LLM keys) to autonomously detect, diagnose, and remediate issues via GitOps.

## System Architecture

```mermaid
graph TB
    subgraph "Kubernetes Cluster — Read-Only Access"
        Events[K8s Events]
        Logs[Pod Logs]
        Nodes[Node Conditions]
        Net[Network Telemetry]
        Metrics[Resource Metrics]
        CRDs[Aotanami CRDs]
    end

    subgraph "Aotanami Operator"
        direction TB

        subgraph "Detection Layer"
            Monitor[Real-Time Monitor]
            Scanner[Security Scanner]
            ComplianceEng[Compliance Engine]
            CostEng[Cost Optimizer]
            AnomalyDet[Anomaly Detector]
            ThreatDet[Threat Detector]
            DriftDet[Drift Detector]
        end

        subgraph "Intelligence Layer"
            Correlator[Incident Correlator]
            PolicyEng[Policy Engine — CEL]
            LLMEng[LLM Engine — BYO Keys]
        end

        subgraph "Action Layer"
            Remediation[GitOps Fix Generator]
            Notifier[Notification Router]
        end

        subgraph "Platform Layer"
            Dashboard[Embedded Dashboard]
            API[REST API]
            MetricsExp[Prometheus / OTEL]
        end
    end

    subgraph "External Integrations"
        GitHub[GitHub App — PRs]
        Slack[Slack / Teams / PagerDuty]
        AlertMgr[AlertManager]
        Telegram[Telegram / WhatsApp]
    end

    Events & Logs & Nodes & Net & Metrics --> Monitor
    CRDs --> Scanner & ComplianceEng & CostEng
    Monitor --> AnomalyDet & ThreatDet
    Scanner --> DriftDet
    AnomalyDet & Scanner & CostEng & ThreatDet & ComplianceEng & DriftDet --> Correlator
    Correlator --> PolicyEng --> LLMEng
    LLMEng --> Remediation --> GitHub
    LLMEng --> Notifier --> Slack & AlertMgr & Telegram
    Monitor & LLMEng --> Dashboard
    API --> Dashboard
    Monitor --> MetricsExp
```

## Operator Lifecycle

```mermaid
sequenceDiagram
    participant K8s as Kubernetes API
    participant Mon as Monitor
    participant Cor as Correlator
    participant Pol as Policy Engine
    participant LLM as LLM Engine
    participant Rem as Remediation
    participant Not as Notifier

    K8s->>Mon: Watch events, logs, metrics
    Mon->>Mon: Detect anomaly / threat
    Mon->>Cor: Forward findings
    Cor->>Cor: Deduplicate & correlate
    Cor->>Pol: Evaluate against policies
    Pol->>Pol: CEL expression evaluation

    alt Complex / Novel Issue
        Pol->>LLM: Request AI diagnosis
        LLM->>LLM: Analyze with structured output
        LLM-->>Rem: Generate fix recommendation
    end

    alt Protect Mode
        Rem->>Rem: Generate manifest patch
        Rem->>K8s: Create PR via GitHub App
    end

    Pol->>Not: Route alert
    Not->>Not: Rate limit & aggregate
    Not-->>Not: Send to configured channels
```

## Core Components

### Controllers (Kubebuilder-generated)

Each CRD has a dedicated reconciliation controller:

| Controller | Watches | Reconciles |
|---|---|---|
| SecurityPolicyReconciler | SecurityPolicy | Configures scanner rules, triggers evaluations |
| RemediationPolicyReconciler | RemediationPolicy | Manages GitOps PR generation settings |
| ClusterScanReconciler | ClusterScan | Schedules and executes scans |
| ScanReportReconciler | ScanReport | Manages scan result lifecycle |
| CostPolicyReconciler | CostPolicy | Configures cost monitoring thresholds |
| MonitoringPolicyReconciler | MonitoringPolicy | Configures real-time monitoring |
| NotificationChannelReconciler | NotificationChannel | Validates and activates notification channels |
| AotanamiConfigReconciler | AotanamiConfig | Applies global configuration changes |
| GitOpsRepositoryReconciler | GitOpsRepository | Onboards repos, manages sync lifecycle |

### Internal Packages

| Layer | Package | Purpose |
|---|---|---|
| Intelligence | `llm` | BYO LLM client with token optimization |
| Intelligence | `anomaly` | Statistical anomaly detection |
| Intelligence | `correlator` | Incident dedup & correlation |
| Intelligence | `policy` | CEL-based policy evaluation |
| Detection | `monitor` | Real-time K8s event/log watcher |
| Detection | `scanner` | Security & config scanning |
| Detection | `compliance` | CIS, NSA, PCI-DSS, SOC2, HIPAA |
| Detection | `supplychain` | SBOM, image signatures, CVEs |
| Detection | `threat` | Runtime threat detection |
| Detection | `drift` | Config drift vs. GitOps repo |
| Detection | `costoptimizer` | Resource rightsizing & cost analysis |
| Actions | `remediation` | GitOps fix generator |
| Actions | `gitops` | Repo onboarding & sync |
| Actions | `github` | GitHub App client |
| Actions | `notifier` | Multi-channel alert routing |
| Platform | `dashboard` | Embedded web UI (htmx + SSE) |
| Platform | `api` | REST API (OpenAPI) |
| Platform | `metrics` | Prometheus + OTEL export |
| Platform | `multicluster` | Cross-cluster federation |

## Data Flow

```mermaid
flowchart LR
    A[K8s Events/Logs/Metrics] -->|Read-Only| B[Monitor]
    B --> C{Correlator}
    C -->|Deduplicated| D[Policy Engine]
    D -->|Complex Issues| E[LLM Engine]
    D -->|Simple Issues| F[Notifier]
    E -->|Protect Mode| G[GitOps PR]
    E -->|Audit Mode| F
    E --> H[Dashboard]
    B --> I[Prometheus/OTEL]
```

## Security Model

- **Read-only cluster access**: Aotanami uses only `get`, `list`, `watch` verbs on cluster resources
- **No direct mutations**: All fixes are delivered as GitOps PRs, never applied directly
- **API key isolation**: LLM API keys stored in Kubernetes Secrets, never logged or exposed
- **Non-root container**: Runs as UID 65532 in a distroless image with read-only rootfs
- **Signed artifacts**: All container images and Helm charts are Cosign-signed with SBOM attestations
