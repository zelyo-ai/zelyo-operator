/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/conditions"
	"github.com/zelyo-ai/zelyo-operator/internal/correlator"
	"github.com/zelyo-ai/zelyo-operator/internal/github"
	zelyometrics "github.com/zelyo-ai/zelyo-operator/internal/metrics"
	"github.com/zelyo-ai/zelyo-operator/internal/remediation"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// RemediationPolicyReconciler reconciles a RemediationPolicy object.
// It queries the correlator for open incidents, generates remediation plans
// via the LLM, and submits GitOps PRs for detected violations.
type RemediationPolicyReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Recorder          record.EventRecorder
	CorrelatorEngine  *correlator.Engine  // Shared correlator for incident queries.
	RemediationEngine *remediation.Engine // Generates plans & PRs from findings.
}

// +kubebuilder:rbac:groups=zelyo.ai,resources=remediationpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=remediationpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=remediationpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=zelyo.ai,resources=gitopsrepositories,verbs=get;list;watch
// +kubebuilder:rbac:groups=zelyo.ai,resources=securitypolicies,verbs=get;list;watch

// Reconcile implements the active remediation loop:
// 1. Validate GitOpsRepository & SecurityPolicies
// 2. Query correlator for open incidents
// 3. For matching incidents, generate remediation plans via LLM
// 4. Submit GitOps PRs (or dry-run/report)
// 5. Update status with PR counts
func (r *RemediationPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		zelyometrics.ReconcileDuration.WithLabelValues("remediationpolicy").Observe(time.Since(start).Seconds())
	}()

	policy := &zelyov1alpha1.RemediationPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching RemediationPolicy: %w", err)
	}

	log.Info("Reconciling RemediationPolicy", "name", policy.Name,
		"gitopsRepo", policy.Spec.GitOpsRepository, "dryRun", policy.Spec.DryRun,
		"severityFilter", policy.Spec.SeverityFilter)

	// Mark as reconciling.
	conditions.MarkReconciling(&policy.Status.Conditions, "Reconciliation in progress", policy.Generation)

	// ── Step 1: Validate GitOpsRepository ──
	repo := &zelyov1alpha1.GitOpsRepository{}
	repoKey := types.NamespacedName{Name: policy.Spec.GitOpsRepository, Namespace: policy.Namespace}
	if err := r.Get(ctx, repoKey, repo); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
				fmt.Sprintf("GitOpsRepository %q not found", policy.Spec.GitOpsRepository))
			conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionGitOpsConnected,
				zelyov1alpha1.ReasonTargetNotFound,
				fmt.Sprintf("GitOpsRepository %q not found", policy.Spec.GitOpsRepository), policy.Generation)
			conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
				zelyov1alpha1.ReasonTargetNotFound, "Referenced GitOpsRepository not found", policy.Generation)
			policy.Status.Phase = zelyov1alpha1.PhaseError
			policy.Status.ObservedGeneration = policy.Generation
			if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
			}
			return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching GitOpsRepository: %w", err)
	}

	conditions.MarkTrue(&policy.Status.Conditions, zelyov1alpha1.ConditionGitOpsConnected,
		zelyov1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("GitOpsRepository %q is available (phase: %s)", repo.Name, repo.Status.Phase), policy.Generation)

	// ── Step 2: Validate targeted SecurityPolicies ──
	// Non-NotFound errors previously fell through silently; track missing
	// and errored targets explicitly so we can mark a degraded condition
	// and requeue with backoff.
	var missingTargets []string
	if len(policy.Spec.TargetPolicies) > 0 {
		for _, policyName := range policy.Spec.TargetPolicies {
			sp := &zelyov1alpha1.SecurityPolicy{}
			spKey := types.NamespacedName{Name: policyName, Namespace: policy.Namespace}
			if err := r.Get(ctx, spKey, sp); err != nil {
				if errors.IsNotFound(err) {
					missingTargets = append(missingTargets, policyName)
					r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
						fmt.Sprintf("Target SecurityPolicy %q not found", policyName))
					continue
				}
				return ctrl.Result{}, fmt.Errorf("fetching target SecurityPolicy %q: %w", policyName, err)
			}
		}
	}
	if len(missingTargets) > 0 {
		conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileFailed,
			fmt.Sprintf("target SecurityPolicies not found: %s", strings.Join(missingTargets, ", ")),
			policy.Generation)
		policy.Status.Phase = zelyov1alpha1.PhaseError
		policy.Status.ObservedGeneration = policy.Generation
		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
		return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
	}

	// ── Step 3: Query correlator for open incidents ──
	var prsCreated, openPRs int32
	if r.CorrelatorEngine != nil && r.RemediationEngine != nil {
		prsCreated, openPRs = r.processIncidents(ctx, policy, repo)
	} else {
		log.Info("Correlator or remediation engine not configured — skipping active remediation")
	}

	// ── Step 4: Update status ──
	now := metav1.Now()
	policy.Status.Phase = zelyov1alpha1.PhaseActive
	policy.Status.LastRun = &now
	policy.Status.RemediationsApplied += prsCreated
	// OpenPRs reflects the total count of open Zelyo-generated PRs in the
	// target repo after this cycle: already-open PRs observed at the start
	// plus any this cycle opened.
	policy.Status.OpenPRs = openPRs + prsCreated
	policy.Status.ObservedGeneration = policy.Generation
	conditions.MarkTrue(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("RemediationPolicy is active (PRs created this cycle: %d, total: %d)",
			prsCreated, policy.Status.RemediationsApplied), policy.Generation)

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, zelyov1alpha1.EventReasonReconciled,
		fmt.Sprintf("RemediationPolicy reconciled (repo=%s, dryRun=%v, prsCreated=%d, severity>=%s)",
			policy.Spec.GitOpsRepository, policy.Spec.DryRun, prsCreated, policy.Spec.SeverityFilter))

	zelyometrics.ReconcileTotal.WithLabelValues("remediationpolicy", "success").Inc()
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// processIncidents queries the correlator for open incidents, filters by severity,
// generates remediation plans, and optionally submits PRs.
//
// Returns (prsCreated, openPRs) where openPRs is the number of Zelyo-generated
// PRs already open on the target repo *at the start of this cycle* — i.e.
// before any PR this cycle may have created. Callers combine them to derive
// status.openPRs.
func (r *RemediationPolicyReconciler) processIncidents(
	ctx context.Context,
	policy *zelyov1alpha1.RemediationPolicy,
	repo *zelyov1alpha1.GitOpsRepository,
) (prsCreated, openPRs int32) {
	log := logf.FromContext(ctx)

	incidents := r.CorrelatorEngine.GetOpenIncidents()
	if len(incidents) == 0 {
		log.Info("No open incidents found — nothing to remediate")
		// Even with no incidents, surface the current open-PR count to
		// status so users can see it via `kubectl get remediationpolicy`.
		return 0, r.countOpenPRs(ctx, policy, repo)
	}

	log.Info("Found open incidents", "count", len(incidents))

	// Determine severity threshold.
	severityFilter := policy.Spec.SeverityFilter
	if severityFilter == "" {
		severityFilter = "high"
	}
	minSev := severityOrder[severityFilter]

	// ── Step 3: Initialize GitOps Engine from Secret ──
	r.ensureGitOpsEngineFromSecret(ctx, repo)

	// Respect MaxConcurrentPRs limit.
	maxPRs := policy.Spec.MaxConcurrentPRs
	if maxPRs == 0 {
		maxPRs = 5
	}

	// Parse repo owner/name from URL for PR submission.
	repoOwner, repoName := parseRepoURL(repo.Spec.URL)

	// Count already-open Zelyo-generated PRs on the target repo so the
	// MaxConcurrentPRs cap is honored across reconciles, not just within
	// a single cycle.
	openPRs = r.countOpenPRsForProvider(ctx, policy, repoOwner, repoName)
	budget := maxPRs - openPRs
	if budget <= 0 {
		log.Info("MaxConcurrentPRs budget exhausted by already-open PRs — skipping",
			"limit", maxPRs, "openPRs", openPRs)
		return 0, openPRs
	}

	for _, incident := range incidents {
		if prsCreated >= budget {
			log.Info("MaxConcurrentPRs budget reached this cycle",
				"limit", maxPRs, "openPRs", openPRs, "createdThisCycle", prsCreated)
			break
		}

		// Filter by severity.
		incSev, ok := severityOrder[incident.Severity]
		if !ok {
			continue
		}
		if incSev > minSev {
			continue // Incident severity is below threshold.
		}

		// Convert incident to a scanner.Finding for the remediation engine.
		finding := incidentToFinding(incident)

		// Generate remediation plan.
		plan, err := r.RemediationEngine.GeneratePlan(ctx, finding)
		if err != nil {
			log.Error(err, "Failed to generate remediation plan",
				"incident", incident.ID,
				"resource", fmt.Sprintf("%s/%s", incident.Namespace, incident.Resource))
			r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
				fmt.Sprintf("LLM plan generation failed for incident %s: %v", incident.ID, err))
			continue
		}

		log.Info("Generated remediation plan",
			"incident", incident.ID,
			"fixes", len(plan.Fixes),
			"riskScore", plan.RiskScore,
			"dryRun", policy.Spec.DryRun)

		// Apply the plan (strategy is configured on the remediation engine).
		result, err := r.RemediationEngine.ApplyPlan(ctx, plan, repoOwner, repoName)
		if err != nil {
			log.Error(err, "Failed to apply remediation plan",
				"incident", incident.ID)
			r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
				fmt.Sprintf("Failed to apply fix for incident %s: %v", incident.ID, err))
			continue
		}

		if result != nil {
			log.Info("Remediation PR created",
				"incident", incident.ID,
				"prURL", result.URL)
			r.Recorder.Event(policy, corev1.EventTypeNormal, "RemediationPRCreated",
				fmt.Sprintf("Created PR %s for incident %s (risk=%d)",
					result.URL, incident.ID, plan.RiskScore))
		}

		// Resolve the incident after successful remediation.
		r.CorrelatorEngine.ResolveIncident(incident.ID)
		prsCreated++
	}

	return prsCreated, openPRs
}

// ensureGitOpsEngineFromSecret reads the repo's AuthSecret (if any) and,
// when a usable PAT/app token is present, constructs a GitHub engine and
// registers it on the remediation engine. The function is deliberately
// permissive: a missing secret, unreadable secret, or empty token
// silently leaves whatever GitOps engine is already configured in place
// (including injected test engines) — there is no visible error
// condition because the surrounding reconciler handles missing creds by
// degrading gracefully to no-op remediation.
func (r *RemediationPolicyReconciler) ensureGitOpsEngineFromSecret(
	ctx context.Context,
	repo *zelyov1alpha1.GitOpsRepository,
) {
	if repo.Spec.AuthSecret == "" {
		return
	}
	log := logf.FromContext(ctx)
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: repo.Spec.AuthSecret, Namespace: repo.Namespace}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return
	}
	token := string(secret.Data["token"])
	if token == "" {
		token = string(secret.Data["api-key"])
	}
	if token == "" {
		return
	}
	ghClient := github.NewPATClient(token, "")
	ghEngine := github.NewEngine(ghClient, log.WithName("github-engine"))
	r.RemediationEngine.SetGitOpsEngine(ghEngine)
	log.Info("Successfully initialized GitOps engine for remediation", "repo", repo.Name)
}

// countOpenPRs resolves the repo owner/name from the GitOpsRepository spec
// and delegates to countOpenPRsForProvider.
func (r *RemediationPolicyReconciler) countOpenPRs(
	ctx context.Context,
	policy *zelyov1alpha1.RemediationPolicy,
	repo *zelyov1alpha1.GitOpsRepository,
) int32 {
	repoOwner, repoName := parseRepoURL(repo.Spec.URL)
	return r.countOpenPRsForProvider(ctx, policy, repoOwner, repoName)
}

// countOpenPRsForProvider queries the configured GitOps provider for the
// number of currently-open Zelyo-generated PRs on owner/repo. The provider's
// ListOpenPRs implementation is already expected to filter out non-Zelyo
// PRs (by branch-prefix convention or labels).
//
// Errors are logged and treated as zero: a transient provider failure
// must not permanently block remediation. Callers still respect the
// per-cycle loop bound, so the worst case is a temporarily-inflated
// per-cycle budget during provider outages.
//
// When multiple RemediationPolicies target the same repo, they share the
// open-PR count (the cap is applied per repo, not per policy). Per-policy
// scoping requires PRTemplate.BranchPrefix to be both configurable and
// actually propagated into the branch name — that wiring is not yet in
// place (BranchName hardcodes its prefix), so adding a prefix filter here
// would silently match zero PRs under the default config and re-break
// the cap we are fixing.
func (r *RemediationPolicyReconciler) countOpenPRsForProvider(
	ctx context.Context,
	_ *zelyov1alpha1.RemediationPolicy,
	owner, repo string,
) int32 {
	log := logf.FromContext(ctx)

	if owner == "" || repo == "" {
		return 0
	}
	if r.RemediationEngine == nil {
		return 0
	}
	ge := r.RemediationEngine.GitOpsEngineForRepo(owner, repo)
	if ge == nil {
		return 0
	}

	existing, err := ge.ListOpenPRs(ctx, owner, repo)
	if err != nil {
		log.Error(err, "Failed to list open PRs — treating as zero for this cycle",
			"owner", owner, "repo", repo)
		return 0
	}
	//nolint:gosec // len bounded by GitHub API page size (100).
	return int32(len(existing))
}

// incidentToFinding converts a correlator incident to a scanner finding for the
// remediation engine. Uses the most recent event's details.
func incidentToFinding(incident *correlator.Incident) *scanner.Finding {
	f := &scanner.Finding{
		Title:             incident.Title,
		Severity:          incident.Severity,
		ResourceNamespace: incident.Namespace,
		ResourceName:      incident.Resource,
		Description:       fmt.Sprintf("Correlated incident %s with %d events", incident.ID, len(incident.Events)),
	}

	// Enrich from events if available.
	if len(incident.Events) > 0 {
		latest := incident.Events[len(incident.Events)-1]
		f.ResourceKind = latest.ResourceKind
		f.RuleType = string(latest.Type)
		if latest.Message != "" {
			f.Title = latest.Message
		}
	}

	return f
}

// parseRepoURL extracts owner and repo name from a Git URL.
// Handles both HTTPS and SSH URL formats.
func parseRepoURL(url string) (owner, repo string) {
	// Simple heuristic: extract from "github.com/owner/repo" pattern.
	// Works for: https://github.com/owner/repo.git, git@github.com:owner/repo.git
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] != '/' && url[i] != ':' {
			continue
		}

		remainder := url[i+1:]
		// Strip .git suffix.
		if len(remainder) > 4 && remainder[len(remainder)-4:] == ".git" {
			remainder = remainder[:len(remainder)-4]
		}
		repo = remainder

		// Find owner.
		for j := i - 1; j >= 0; j-- {
			if url[j] == '/' || url[j] == ':' || url[j] == '@' {
				owner = url[j+1 : i]
				return owner, repo
			}
		}
		break
	}
	return "", ""
}

// SetupWithManager sets up the controller with the Manager.
func (r *RemediationPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.RemediationPolicy{}).
		Named("remediationpolicy").
		Complete(r)
}
