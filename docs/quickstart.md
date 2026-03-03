# Quick Start Recipes

Practical recipes for common Aotanami use cases. Copy-paste these and modify to fit your environment.

## Recipe 1: Scan All Production Pods for Security Issues

**Goal**: Find every security misconfiguration in your production namespaces.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: SecurityPolicy
metadata:
  name: production-security-baseline
  namespace: aotanami-system
spec:
  severity: medium
  match:
    namespaces: ["production"]
    excludeNamespaces: ["kube-system"]
  rules:
    - name: security-context
      type: container-security-context
      enforce: true
    - name: resource-limits
      type: resource-limits
      enforce: true
    - name: image-pinning
      type: image-vulnerability
      enforce: false
    - name: pod-security
      type: pod-security
      enforce: true
    - name: privilege-escalation
      type: privilege-escalation
      enforce: true
    - name: secrets-exposure
      type: secrets-exposure
      enforce: false
    - name: network-policy
      type: network-policy
      enforce: false
    - name: rbac-audit
      type: rbac-audit
      enforce: false
```

```bash
kubectl apply -f production-security-baseline.yaml

# Check results
kubectl get securitypolicies -n aotanami-system
kubectl describe securitypolicy production-security-baseline -n aotanami-system
```

---

## Recipe 2: Critical-Only Alerting

**Goal**: Only get alerted on critical and high-severity issues — no noise.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: SecurityPolicy
metadata:
  name: critical-only
  namespace: aotanami-system
spec:
  severity: high  # Filter out medium, low, info
  match:
    namespaces: ["production"]
  rules:
    - name: privileged-containers
      type: container-security-context
      enforce: true
    - name: host-access
      type: pod-security
      enforce: true
    - name: root-containers
      type: privilege-escalation
      enforce: true
    - name: hardcoded-secrets
      type: secrets-exposure
      enforce: true
```

---

## Recipe 3: Nightly Full Cluster Scan with Reports

**Goal**: Run all 8 scanners every night at 2 AM, keep 30 days of reports.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: ClusterScan
metadata:
  name: nightly-full-scan
  namespace: aotanami-system
spec:
  schedule: "0 2 * * *"
  scanners:
    - container-security-context
    - resource-limits
    - image-vulnerability
    - pod-security
    - privilege-escalation
    - secrets-exposure
    - network-policy
    - rbac-audit
  scope:
    namespaces: []  # Empty = scan all namespaces
    excludeNamespaces: ["kube-system", "kube-public"]
  historyLimit: 30
  suspend: false
```

```bash
# View recent scan reports
kubectl get scanreports -n aotanami-system --sort-by=.metadata.creationTimestamp

# View the latest report
kubectl describe scanreport $(kubectl get scanreports -n aotanami-system \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}') \
  -n aotanami-system
```

---

## Recipe 4: Cost Optimization

**Goal**: Find pods wasting resources and get rightsizing recommendations.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: CostPolicy
metadata:
  name: optimize-production
  namespace: aotanami-system
spec:
  targetNamespaces: ["production"]
  resizeStrategy: conservative
  budgetLimits:
    monthlyBudgetUSD: "10000"
    costIncreaseThresholdPercent: 15
  idleDetection:
    enabled: true
    cpuThresholdPercent: 5
    memoryThresholdPercent: 5
    idleDurationMinutes: 60
```

```bash
# Check recommendations
kubectl get costpolicy optimize-production -n aotanami-system -o wide
```

---

## Recipe 5: Set Up Slack Alerts

**Goal**: Send security alerts to a Slack channel.

**Step 1**: Create a Slack token secret:

```bash
kubectl create secret generic slack-token \
  --namespace aotanami-system \
  --from-literal=webhook-url=https://hooks.slack.com/services/YOUR_WORKSPACE/YOUR_CHANNEL/YOUR_TOKEN
```

**Step 2**: Create the NotificationChannel:

```yaml
apiVersion: aotanami.com/v1alpha1
kind: NotificationChannel
metadata:
  name: slack-security
  namespace: aotanami-system
spec:
  type: slack
  credentialSecret: slack-token
  severityFilter: high
  rateLimit:
    maxPerHour: 30
    aggregateSeconds: 60
  slack:
    channel: "#security-alerts"
```

**Step 3**: Reference it in a MonitoringPolicy:

```yaml
apiVersion: aotanami.com/v1alpha1
kind: MonitoringPolicy
metadata:
  name: production-monitoring
  namespace: aotanami-system
spec:
  targetNamespaces: ["production"]
  notificationChannels: ["slack-security"]
  eventFilters:
    types: ["Warning"]
    reasons: ["OOMKilled", "CrashLoopBackOff", "FailedScheduling"]
```

---

## Recipe 6: GitOps Automated Remediation

**Goal**: Aotanami automatically creates PRs to fix security issues.

**Step 1**: Create GitHub authentication:

```bash
kubectl create secret generic github-creds \
  --namespace aotanami-system \
  --from-literal=token=ghp_xxxxxxxxxxxxxxxxxxxx
```

**Step 2**: Onboard your GitOps repository:

```yaml
apiVersion: aotanami.com/v1alpha1
kind: GitOpsRepository
metadata:
  name: infra-repo
  namespace: aotanami-system
spec:
  url: https://github.com/my-org/k8s-manifests
  branch: main
  paths: ["clusters/production/"]
  provider: github
  authSecret: github-creds
  enableDriftDetection: true
```

**Step 3**: Create a RemediationPolicy:

```yaml
apiVersion: aotanami.com/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-fix-security
  namespace: aotanami-system
spec:
  targetPolicies: ["production-security-baseline"]
  gitOpsRepository: infra-repo
  prTemplate:
    titlePrefix: "[Aotanami Auto-Fix]"
    labels: ["security", "automated"]
    branchPrefix: "aotanami/fix-"
  severityFilter: high
  maxConcurrentPRs: 3
  dryRun: false
  autoMerge: false
```

---

## Useful kubectl Commands

```bash
# List all Aotanami resources
kubectl get securitypolicies,clusterscans,scanreports,costpolicies,monitoringpolicies,notificationchannels,remediationpolicies,gitopsrepositories,aotanamiconfigs -A

# Check operator health
kubectl get pods -n aotanami-system
kubectl logs -f deploy/aotanami-controller-manager -n aotanami-system

# View events for a specific resource
kubectl events --for securitypolicy/production-security-baseline -n aotanami-system

# Get conditions as JSON (pipe to jq for formatting)
kubectl get securitypolicy my-policy -o jsonpath='{.status.conditions}' | jq .
```
