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

// MonitoringPolicyReconciler reconciles a MonitoringPolicy object.
// It validates the monitoring configuration and sets up event/log watches.
type MonitoringPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=aotanami.com,resources=monitoringpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aotanami.com,resources=monitoringpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aotanami.com,resources=monitoringpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile validates and activates the MonitoringPolicy.
func (r *MonitoringPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &aotanamiv1alpha1.MonitoringPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching MonitoringPolicy: %w", err)
	}

	log.Info("Reconciling MonitoringPolicy", "name", policy.Name, "namespace", policy.Namespace)

	// Validate notification channels exist.
	for _, chName := range policy.Spec.NotificationChannels {
		ch := &aotanamiv1alpha1.NotificationChannel{}
		key := types.NamespacedName{Name: chName, Namespace: policy.Namespace}
		if err := r.Get(ctx, key, ch); err != nil {
			if errors.IsNotFound(err) {
				r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
					fmt.Sprintf("NotificationChannel %q not found", chName))
				conditions.MarkFalse(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
					aotanamiv1alpha1.ReasonTargetNotFound,
					fmt.Sprintf("NotificationChannel %q not found", chName), policy.Generation)
				policy.Status.Phase = aotanamiv1alpha1.PhaseDegraded
				if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
					return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
				}
				return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
			}
			return ctrl.Result{}, fmt.Errorf("checking NotificationChannel: %w", err)
		}
	}

	// Mark as active.
	now := metav1.Now()
	policy.Status.Phase = aotanamiv1alpha1.PhaseActive
	policy.Status.LastEventTime = &now
	conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
		aotanamiv1alpha1.ReasonReconcileSuccess, "Monitoring policy is active", policy.Generation)

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, aotanamiv1alpha1.EventReasonReconciled,
		fmt.Sprintf("MonitoringPolicy reconciled (event types: %v)", policy.Spec.EventFilters.Types))

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MonitoringPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&aotanamiv1alpha1.MonitoringPolicy{}).
		Named("monitoringpolicy").
		Complete(r)
}
