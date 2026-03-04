# Getting Started

Welcome to Aotanami! This guide will walk you through setting up a local development environment and running your first security scan — even if you've never worked with Kubernetes operators before.

## What You'll Need

Before starting, make sure you have these tools installed:

| Tool | Version | Why You Need It |
|---|---|---|
| [Go](https://go.dev/dl/) | 1.24+ | Aotanami is written in Go |
| [Docker](https://docs.docker.com/get-docker/) | Latest | Builds container images |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | Latest | Talks to Kubernetes clusters |
| [kind](https://kind.sigs.k8s.io/) | Latest | Creates a local Kubernetes cluster on your laptop |
| [Kubebuilder](https://kubebuilder.io/) | 4.x | Generates operator scaffolding |
| [Helm](https://helm.sh/docs/intro/install/) | 3.x | Installs Aotanami into a cluster |

!!! tip "Don't have kind?"
    You can also use [minikube](https://minikube.sigs.k8s.io/) or any other local Kubernetes setup. kind is recommended because it's the fastest to start.

## Step 1: Clone the Repository

```bash
git clone https://github.com/aotanami/aotanami.git
cd aotanami
```

## Step 2: Create a Local Cluster

```bash
kind create cluster --name aotanami-dev
```

This creates a single-node Kubernetes cluster running inside Docker. It takes about 30 seconds.

Verify it's running:

```bash
kubectl cluster-info --context kind-aotanami-dev
```

## Step 3: Install Aotanami's CRDs

CRDs (Custom Resource Definitions) teach Kubernetes about Aotanami's resource types — things like `SecurityPolicy` and `ClusterScan`.

```bash
make install
```

Verify the CRDs are installed:

```bash
kubectl get crds | grep aotanami
```

You should see 9 CRDs listed (securitypolicies, clusterscans, scanreports, etc.).

## Step 4: Run the Operator Locally

```bash
make run
```

This starts Aotanami on your laptop, connected to your kind cluster. You'll see log output as it starts up, including:

```
INFO    Scanner registry initialized    {"registeredScanners": ["container-security-context", "resource-limits", ...]}
INFO    Starting Controller Manager
```

!!! note "Leave this terminal running"
    Open a new terminal for the next steps. The operator needs to keep running to process your resources.

## Step 5: Create Your First SecurityPolicy

Save this as `my-first-policy.yaml`:

```yaml
apiVersion: aotanami.com/v1alpha1
kind: SecurityPolicy
metadata:
  name: baseline-security
  namespace: default
spec:
  severity: medium
  match:
    namespaces: ["default"]
  rules:
    - name: check-security-context
      type: container-security-context
      enforce: true
    - name: check-resource-limits
      type: resource-limits
      enforce: true
    - name: check-image-tags
      type: image-vulnerability
      enforce: false
```

Apply it:

```bash
kubectl apply -f my-first-policy.yaml
```

## Step 6: Deploy a Test Workload

Let's deploy a deliberately insecure pod so Aotanami has something to find:

```bash
kubectl run insecure-nginx --image=nginx:latest --restart=Never
```

This pod has several security issues:

- Uses the `:latest` tag (not pinned)
- No resource limits set
- No security context configured (runs as root)

## Step 7: Check What Aotanami Found

Wait a few seconds, then check the SecurityPolicy status:

```bash
kubectl get securitypolicies
```

You should see something like:

```
NAME                SEVERITY   VIOLATIONS   PHASE    AGE
baseline-security   medium     5            Active   30s
```

For detailed findings, describe the policy:

```bash
kubectl describe securitypolicy baseline-security
```

Look at the `Status` section — you'll see:

- **Phase**: `Active` (the policy is working)
- **ViolationCount**: Number of findings
- **Conditions**: Detailed status like `ScanCompleted=True`
- **Events**: Recent scan results

## Step 8: Clean Up

```bash
# Delete the test pod
kubectl delete pod insecure-nginx

# Delete the policy
kubectl delete securitypolicy baseline-security

# Delete the kind cluster (when you're done)
kind delete cluster --name aotanami-dev
```

## Deploying to a Real Cluster

### Via Helm (Recommended)

```bash
# 1. Create the namespace
kubectl create namespace aotanami-system

# 2. Create your LLM API key secret
kubectl create secret generic aotanami-llm \
  --namespace aotanami-system \
  --from-literal=api-key=<YOUR_OPENROUTER_API_KEY>

# 3. Install Aotanami
helm install aotanami oci://ghcr.io/aotanami/charts/aotanami \
  --namespace aotanami-system \
  --set config.llm.provider=openrouter \
  --set config.llm.model=anthropic/claude-sonnet-4-20250514 \
  --set config.llm.apiKeySecret=aotanami-llm

# 4. Verify
kubectl get pods -n aotanami-system
```

### Verify Image Signature

Before deploying to production, verify that the image hasn't been tampered with:

```bash
cosign verify ghcr.io/aotanami/aotanami:<tag> \
  --certificate-identity-regexp='.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

## What's Next?

Now that you've got Aotanami running, explore these guides:

| Guide | What You'll Learn |
|---|---|
| [Quick Start](quickstart.md) | Common recipes for security scanning |
| [CRD Reference](crd-reference.md) | Every field in every CRD explained |
| [Architecture](architecture.md) | How the operator works under the hood |
| [Security Scanners](scanners.md) | What each scanner checks and how to configure it |
| [Monitoring & Metrics](metrics.md) | Prometheus integration and alerting |
| [GitOps Onboarding](gitops-onboarding.md) | Enable Protect Mode with automated PR fixes |
