/*
Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.

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

	aotanamiv1alpha1 "github.com/aotanami/aotanami/api/v1alpha1"
	"github.com/aotanami/aotanami/internal/conditions"
)

// RemediationPolicyReconciler reconciles a RemediationPolicy object.
// It validates the remediation configuration and the referenced GitOpsRepository.
type RemediationPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=aotanami.com,resources=remediationpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aotanami.com,resources=remediationpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aotanami.com,resources=remediationpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=aotanami.com,resources=gitopsrepositories,verbs=get;list;watch
// +kubebuilder:rbac:groups=aotanami.com,resources=securitypolicies,verbs=get;list;watch

// Reconcile validates the RemediationPolicy and its referenced resources.
func (r *RemediationPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &aotanamiv1alpha1.RemediationPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching RemediationPolicy: %w", err)
	}

	log.Info("Reconciling RemediationPolicy", "name", policy.Name,
		"gitopsRepo", policy.Spec.GitOpsRepository, "dryRun", policy.Spec.DryRun)

	// Validate the referenced GitOpsRepository exists.
	repo := &aotanamiv1alpha1.GitOpsRepository{}
	repoKey := types.NamespacedName{Name: policy.Spec.GitOpsRepository, Namespace: policy.Namespace}
	if err := r.Get(ctx, repoKey, repo); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
				fmt.Sprintf("GitOpsRepository %q not found", policy.Spec.GitOpsRepository))
			conditions.MarkFalse(&policy.Status.Conditions, aotanamiv1alpha1.ConditionGitOpsConnected,
				aotanamiv1alpha1.ReasonTargetNotFound,
				fmt.Sprintf("GitOpsRepository %q not found", policy.Spec.GitOpsRepository), policy.Generation)
			conditions.MarkFalse(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
				aotanamiv1alpha1.ReasonTargetNotFound, "Referenced GitOpsRepository not found", policy.Generation)
			policy.Status.Phase = aotanamiv1alpha1.PhaseError
			if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
			}
			return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching GitOpsRepository: %w", err)
	}

	conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionGitOpsConnected,
		aotanamiv1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("GitOpsRepository %q is available (phase: %s)", repo.Name, repo.Status.Phase), policy.Generation)

	// Validate targeted SecurityPolicies if specified.
	if len(policy.Spec.TargetPolicies) > 0 {
		for _, policyName := range policy.Spec.TargetPolicies {
			sp := &aotanamiv1alpha1.SecurityPolicy{}
			spKey := types.NamespacedName{Name: policyName, Namespace: policy.Namespace}
			if err := r.Get(ctx, spKey, sp); err != nil {
				if errors.IsNotFound(err) {
					r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
						fmt.Sprintf("Target SecurityPolicy %q not found", policyName))
				}
			}
		}
	}

	// Mark as active.
	now := metav1.Now()
	policy.Status.Phase = aotanamiv1alpha1.PhaseActive
	policy.Status.LastRun = &now
	conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
		aotanamiv1alpha1.ReasonReconcileSuccess, "RemediationPolicy is active and ready", policy.Generation)

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, aotanamiv1alpha1.EventReasonReconciled,
		fmt.Sprintf("RemediationPolicy reconciled (repo=%s, dryRun=%v, severityFilter=%s)",
			policy.Spec.GitOpsRepository, policy.Spec.DryRun, policy.Spec.SeverityFilter))

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RemediationPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&aotanamiv1alpha1.RemediationPolicy{}).
		Named("remediationpolicy").
		Complete(r)
}
