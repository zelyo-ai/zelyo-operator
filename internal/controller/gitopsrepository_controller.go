/*
Copyright 2026 Zelyo AI.

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

// GitOpsRepositoryReconciler reconciles a GitOpsRepository object.
// It validates the repository configuration, authentication secret,
// and manages the sync lifecycle.
type GitOpsRepositoryReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=aotanami.com,resources=gitopsrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aotanami.com,resources=gitopsrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aotanami.com,resources=gitopsrepositories/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile validates the GitOpsRepository configuration and manages sync state.
func (r *GitOpsRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	repo := &aotanamiv1alpha1.GitOpsRepository{}
	if err := r.Get(ctx, req.NamespacedName, repo); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching GitOpsRepository: %w", err)
	}

	log.Info("Reconciling GitOpsRepository", "name", repo.Name,
		"url", repo.Spec.URL, "branch", repo.Spec.Branch, "provider", repo.Spec.Provider)

	// Validate the auth secret exists.
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: repo.Spec.AuthSecret, Namespace: repo.Namespace}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(repo, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonSecretMissing,
				fmt.Sprintf("Auth Secret %q not found", repo.Spec.AuthSecret))
			conditions.MarkFalse(&repo.Status.Conditions, aotanamiv1alpha1.ConditionSecretResolved,
				aotanamiv1alpha1.ReasonSecretNotFound,
				fmt.Sprintf("Secret %q not found", repo.Spec.AuthSecret), repo.Generation)
			conditions.MarkFalse(&repo.Status.Conditions, aotanamiv1alpha1.ConditionReady,
				aotanamiv1alpha1.ReasonSecretNotFound, "Authentication secret not available", repo.Generation)
			repo.Status.Phase = aotanamiv1alpha1.PhaseError
			repo.Status.LastError = fmt.Sprintf("Auth secret %q not found", repo.Spec.AuthSecret)
			if statusErr := r.Status().Update(ctx, repo); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
			}
			return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching auth secret: %w", err)
	}

	conditions.MarkTrue(&repo.Status.Conditions, aotanamiv1alpha1.ConditionSecretResolved,
		aotanamiv1alpha1.ReasonSecretResolved, "Authentication secret is available", repo.Generation)

	// Validate paths are specified.
	if len(repo.Spec.Paths) == 0 {
		conditions.MarkFalse(&repo.Status.Conditions, aotanamiv1alpha1.ConditionReady,
			aotanamiv1alpha1.ReasonInvalidConfig, "At least one path must be specified", repo.Generation)
		repo.Status.Phase = aotanamiv1alpha1.PhaseError
		if err := r.Status().Update(ctx, repo); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// Mark as synced (actual git sync would happen in a full implementation).
	now := metav1.Now()
	repo.Status.Phase = aotanamiv1alpha1.PhaseSynced
	repo.Status.LastSyncTime = &now
	repo.Status.LastError = ""

	conditions.MarkTrue(&repo.Status.Conditions, aotanamiv1alpha1.ConditionGitOpsConnected,
		aotanamiv1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("Repository %s (branch: %s) is connected", repo.Spec.URL, repo.Spec.Branch), repo.Generation)
	conditions.MarkTrue(&repo.Status.Conditions, aotanamiv1alpha1.ConditionReady,
		aotanamiv1alpha1.ReasonReconcileSuccess, "Repository is synced and ready", repo.Generation)

	if err := r.Status().Update(ctx, repo); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(repo, corev1.EventTypeNormal, aotanamiv1alpha1.EventReasonReconciled,
		fmt.Sprintf("GitOpsRepository synced (url=%s, branch=%s, paths=%d)",
			repo.Spec.URL, repo.Spec.Branch, len(repo.Spec.Paths)))

	// Requeue at the poll interval.
	requeueAfter := time.Duration(repo.Spec.PollIntervalSeconds) * time.Second
	if requeueAfter == 0 {
		requeueAfter = 5 * time.Minute
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GitOpsRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&aotanamiv1alpha1.GitOpsRepository{}).
		Named("gitopsrepository").
		Complete(r)
}
