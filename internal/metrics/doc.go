// Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.
// SPDX-License-Identifier: Apache-2.0

// Package metrics provides Prometheus metrics and OpenTelemetry tracing for Aotanami.
//
// # Architecture
//
// The metrics package exports operational telemetry:
//
// Prometheus Metrics:
//
//   - aotanami_incidents_total: Counter of detected incidents by severity
//   - aotanami_scans_total: Counter of completed scans by type
//   - aotanami_findings_total: Gauge of active findings by severity
//   - aotanami_remediations_total: Counter of PRs created
//   - aotanami_llm_tokens_total: Counter of LLM tokens consumed
//   - aotanami_llm_requests_total: Counter of LLM API calls
//   - aotanami_notifications_total: Counter of notifications sent by channel
//   - aotanami_drift_resources: Gauge of resources with config drift
//   - aotanami_cost_estimated_monthly: Gauge of estimated monthly cluster cost
//
// OpenTelemetry Tracing:
//
//   - Traces for scan execution, LLM calls, and PR creation workflows
//   - Configurable OTLP exporter endpoint via AotanamiConfig
package metrics
