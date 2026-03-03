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

// Package metrics exposes custom Prometheus metrics for the Aotanami operator.
// These metrics follow the conventions established by kube-state-metrics and
// the Kubernetes Instrumentation SIG.
//
// All metrics use the "aotanami_" prefix and are registered automatically
// when the package is imported.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// ── Reconcile Metrics ──

	// ReconcileTotal counts the total number of reconcile operations per controller.
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aotanami",
			Subsystem: "controller",
			Name:      "reconcile_total",
			Help:      "Total number of reconcile operations by controller and result.",
		},
		[]string{"controller", "result"}, // result: success, error, requeue
	)

	// ReconcileDuration tracks the duration of reconcile operations.
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "aotanami",
			Subsystem: "controller",
			Name:      "reconcile_duration_seconds",
			Help:      "Duration of reconcile operations in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"controller"},
	)

	// ── Scanner Metrics ──

	// ScanFindingsTotal counts findings produced by scanners, by severity.
	ScanFindingsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aotanami",
			Subsystem: "scanner",
			Name:      "findings_total",
			Help:      "Total number of security findings by scanner and severity.",
		},
		[]string{"scanner", "severity"},
	)

	// ScanDuration tracks the duration of scan operations.
	ScanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "aotanami",
			Subsystem: "scanner",
			Name:      "scan_duration_seconds",
			Help:      "Duration of scan operations in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"scanner"},
	)

	// ResourcesScannedTotal counts total resources scanned.
	ResourcesScannedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aotanami",
			Subsystem: "scanner",
			Name:      "resources_scanned_total",
			Help:      "Total number of resources scanned by scanner type.",
		},
		[]string{"scanner"},
	)

	// ── Policy Metrics ──

	// PolicyViolationsGauge tracks the current number of violations per policy.
	PolicyViolationsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "aotanami",
			Subsystem: "policy",
			Name:      "violations",
			Help:      "Current number of violations per security policy.",
		},
		[]string{"policy", "namespace", "severity"},
	)

	// PolicyPhaseGauge tracks the current phase of each policy.
	PolicyPhaseGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "aotanami",
			Subsystem: "policy",
			Name:      "phase_info",
			Help:      "Current phase of each policy (1 = active).",
		},
		[]string{"policy", "namespace", "phase"},
	)

	// ── ClusterScan Metrics ──

	// ClusterScanCompletedTotal counts completed scans.
	ClusterScanCompletedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "aotanami",
			Subsystem: "clusterscan",
			Name:      "completed_total",
			Help:      "Total number of completed cluster scans.",
		},
		[]string{"scan", "namespace"},
	)

	// ClusterScanFindingsGauge tracks the latest findings count per scan.
	ClusterScanFindingsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "aotanami",
			Subsystem: "clusterscan",
			Name:      "findings",
			Help:      "Number of findings from the last cluster scan run.",
		},
		[]string{"scan", "namespace"},
	)

	// ── Cost Metrics ──

	// CostRightsizingGauge tracks the number of rightsizing recommendations.
	CostRightsizingGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "aotanami",
			Subsystem: "cost",
			Name:      "rightsizing_recommendations",
			Help:      "Number of pending rightsizing recommendations.",
		},
		[]string{"policy", "namespace"},
	)
)

func init() {
	// Register all custom metrics with the controller-runtime metrics registry.
	metrics.Registry.MustRegister(
		ReconcileTotal,
		ReconcileDuration,
		ScanFindingsTotal,
		ScanDuration,
		ResourcesScannedTotal,
		PolicyViolationsGauge,
		PolicyPhaseGauge,
		ClusterScanCompletedTotal,
		ClusterScanFindingsGauge,
		CostRightsizingGauge,
	)
}
