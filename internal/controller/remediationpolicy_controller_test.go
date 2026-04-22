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
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/correlator"
	"github.com/zelyo-ai/zelyo-operator/internal/gitops"
	"github.com/zelyo-ai/zelyo-operator/internal/llm"
	"github.com/zelyo-ai/zelyo-operator/internal/remediation"
)

// budgetTestGitOpsEngine is a stub gitops.Engine for the maxConcurrentPRs
// budget tests. ListOpenPRs returns a fixed list to simulate PRs already
// open on the provider. CreatePullRequest records each call so the test
// can assert that no new PRs were created when the budget is exhausted.
type budgetTestGitOpsEngine struct {
	openPRs     []gitops.PullRequestResult
	createCalls atomic.Int32
}

func (f *budgetTestGitOpsEngine) CreatePullRequest(_ context.Context, pr *gitops.PullRequest) (*gitops.PullRequestResult, error) {
	f.createCalls.Add(1)
	return &gitops.PullRequestResult{
		Number:    int(f.createCalls.Load()),
		URL:       "https://github.com/fake/repo/pull/" + pr.HeadBranch,
		Branch:    pr.HeadBranch,
		CreatedAt: time.Now(),
	}, nil
}

func (f *budgetTestGitOpsEngine) GetFile(_ context.Context, _, _, _, _ string) ([]byte, error) {
	return nil, nil
}

func (f *budgetTestGitOpsEngine) ListOpenPRs(_ context.Context, _, _ string) ([]gitops.PullRequestResult, error) {
	return f.openPRs, nil
}

func (f *budgetTestGitOpsEngine) Close() error { return nil }

// budgetTestLLMClient is a no-op LLM — the budget-exhausted path must not
// reach plan generation. If any test accidentally triggers Complete, the
// call count exposes the regression.
type budgetTestLLMClient struct {
	calls atomic.Int32
}

func (f *budgetTestLLMClient) Complete(_ context.Context, _ llm.Request) (*llm.Response, error) {
	f.calls.Add(1)
	return &llm.Response{Content: `{"analysis":"x","fixes":[]}`, Model: "fake"}, nil
}
func (f *budgetTestLLMClient) Provider() llm.Provider { return "fake" }
func (f *budgetTestLLMClient) Close() error           { return nil }

var _ = Describe("RemediationPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		remediationpolicy := &zelyov1alpha1.RemediationPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind RemediationPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, remediationpolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &zelyov1alpha1.RemediationPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: zelyov1alpha1.RemediationPolicySpec{
						GitOpsRepository: "test-repo",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &zelyov1alpha1.RemediationPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance RemediationPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &RemediationPolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: record.NewFakeRecorder(100),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})

	// Regression guard for the maxConcurrentPRs cap. Historically the cap
	// was enforced as a per-reconcile-cycle bound only: prsCreated started
	// at 0 every cycle and the loop broke when that counter hit the cap.
	// With a 5-minute requeue and the same budget each cycle, a policy
	// with maxConcurrentPRs: 3 could accumulate dozens of open PRs.
	//
	// Fix: count already-open PRs on the provider at the start of each
	// cycle and subtract from the cap to get the per-cycle budget. When
	// the provider already has `maxConcurrentPRs` open, no new PRs should
	// be created until existing ones merge or close.
	Context("When maxConcurrentPRs is already reached by open PRs", func() {
		const (
			policyName = "budget-test-policy"
			repoName   = "budget-test-repo"
			ns         = "default"
		)

		ctx := context.Background()
		policyKey := types.NamespacedName{Name: policyName, Namespace: ns}
		repoKey := types.NamespacedName{Name: repoName, Namespace: ns}

		BeforeEach(func() {
			By("creating a GitOpsRepository for the policy to target")
			// AuthSecret references a Secret that does not exist. The
			// controller tolerates the missing secret (silently skips
			// GitOps-engine initialization from the Secret) which leaves
			// our pre-registered fake gitops engine in place on the
			// remediation engine — exactly what this test needs.
			repo := &zelyov1alpha1.GitOpsRepository{
				ObjectMeta: metav1.ObjectMeta{Name: repoName, Namespace: ns},
				Spec: zelyov1alpha1.GitOpsRepositorySpec{
					URL:        "https://github.com/zelyo-ai/budget-test.git",
					Branch:     "main",
					Paths:      []string{"."},
					Provider:   "github",
					AuthSecret: "nonexistent-secret",
				},
			}
			Expect(k8sClient.Create(ctx, repo)).To(Succeed())

			By("creating a RemediationPolicy with maxConcurrentPRs=3")
			policy := &zelyov1alpha1.RemediationPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: ns},
				Spec: zelyov1alpha1.RemediationPolicySpec{
					GitOpsRepository: repoName,
					MaxConcurrentPRs: 3,
					SeverityFilter:   "high",
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		AfterEach(func() {
			policy := &zelyov1alpha1.RemediationPolicy{}
			if err := k8sClient.Get(ctx, policyKey, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
			repo := &zelyov1alpha1.GitOpsRepository{}
			if err := k8sClient.Get(ctx, repoKey, repo); err == nil {
				Expect(k8sClient.Delete(ctx, repo)).To(Succeed())
			}
		})

		It("does not create new PRs and records openPRs in status", func() {
			By("priming the correlator with two events that form a high-severity incident")
			corrEngine := correlator.NewEngine(&correlator.Config{CorrelationWindow: 5 * time.Minute})
			corrEngine.Ingest(&correlator.Event{
				Type:      correlator.EventSecurityViolation,
				Severity:  "high",
				Namespace: "prod",
				Resource:  "nginx",
				Message:   "Privileged container",
			})
			incident := corrEngine.Ingest(&correlator.Event{
				Type:      correlator.EventAnomaly,
				Severity:  "high",
				Namespace: "prod",
				Resource:  "nginx",
				Message:   "Restart spike",
			})
			Expect(incident).NotTo(BeNil(),
				"correlator must surface an open incident so the controller enters the budget check")

			By("wiring a fake gitops engine that reports 3 already-open PRs")
			fakeGit := &budgetTestGitOpsEngine{
				openPRs: []gitops.PullRequestResult{
					{Number: 11, Branch: "zelyo-operator/fix/a", URL: "https://example/1"},
					{Number: 12, Branch: "zelyo-operator/fix/b", URL: "https://example/2"},
					{Number: 13, Branch: "zelyo-operator/fix/c", URL: "https://example/3"},
				},
			}
			fakeLLM := &budgetTestLLMClient{}
			remEngine := remediation.NewEngine(fakeLLM, fakeGit,
				remediation.EngineConfig{Strategy: remediation.StrategyGitOpsPR},
				logr.Discard())

			controllerReconciler := &RemediationPolicyReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Recorder:          record.NewFakeRecorder(100),
				CorrelatorEngine:  corrEngine,
				RemediationEngine: remEngine,
			}

			By("reconciling the policy")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("asserting no new PRs were created")
			Expect(fakeGit.createCalls.Load()).To(Equal(int32(0)),
				"CreatePullRequest must not run when the cap is already met by open PRs")
			Expect(fakeLLM.calls.Load()).To(Equal(int32(0)),
				"LLM plan generation must be skipped when the cap is already met")

			By("asserting the open incident was not resolved")
			Expect(corrEngine.GetOpenIncidents()).To(HaveLen(1),
				"the incident must remain open for a later cycle after existing PRs merge")

			By("asserting status.openPRs reflects the provider count")
			var updated zelyov1alpha1.RemediationPolicy
			Expect(k8sClient.Get(ctx, policyKey, &updated)).To(Succeed())
			Expect(updated.Status.OpenPRs).To(Equal(int32(3)))
			Expect(updated.Status.RemediationsApplied).To(Equal(int32(0)))
		})
	})
})
