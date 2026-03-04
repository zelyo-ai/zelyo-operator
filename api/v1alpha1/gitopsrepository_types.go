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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GitOpsRepositorySpec defines the desired state of GitOpsRepository.
// A GitOpsRepository represents an onboarded GitOps repository that Aotanami
// uses for config drift detection and submitting remediation PRs.
type GitOpsRepositorySpec struct {
	// url is the Git repository URL (HTTPS or SSH).
	// +required
	URL string `json:"url"`

	// branch is the target branch for PRs and drift comparison.
	// +kubebuilder:default=main
	// +optional
	Branch string `json:"branch,omitempty"`

	// paths lists the directories within the repo containing Kubernetes manifests.
	// +kubebuilder:validation:MinItems=1
	// +required
	Paths []string `json:"paths"`

	// provider identifies the Git hosting provider.
	// +kubebuilder:validation:Enum=github;gitlab;bitbucket
	// +kubebuilder:default=github
	// +optional
	Provider string `json:"provider,omitempty"`

	// authSecret is the name of the Kubernetes Secret containing authentication credentials.
	// For GitHub App, use the GitHub App credentials. For PAT, use a token.
	// +required
	AuthSecret string `json:"authSecret"`

	// syncStrategy defines how Aotanami syncs with the repository.
	// +kubebuilder:validation:Enum=poll;webhook
	// +kubebuilder:default=poll
	// +optional
	SyncStrategy string `json:"syncStrategy,omitempty"`

	// pollIntervalSeconds is how frequently to poll the repo for changes (when syncStrategy is poll).
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:default=300
	// +optional
	PollIntervalSeconds int32 `json:"pollIntervalSeconds,omitempty"`

	// namespaceMapping maps repository paths to Kubernetes namespaces for drift detection.
	// +optional
	NamespaceMapping []NamespaceMap `json:"namespaceMapping,omitempty"`

	// enableDriftDetection when true, enables comparing live cluster state against repo manifests.
	// +kubebuilder:default=true
	// +optional
	EnableDriftDetection bool `json:"enableDriftDetection,omitempty"`
}

// NamespaceMap maps a path in the GitOps repo to a Kubernetes namespace.
type NamespaceMap struct {
	// repoPath is the path within the git repository.
	// +required
	RepoPath string `json:"repoPath"`

	// namespace is the Kubernetes namespace this path corresponds to.
	// +required
	Namespace string `json:"namespace"`
}

// GitOpsRepositoryStatus defines the observed state of GitOpsRepository.
type GitOpsRepositoryStatus struct {
	// phase indicates the current lifecycle phase.
	// +kubebuilder:validation:Enum=Pending;Syncing;Synced;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// lastSyncedCommit is the SHA of the last successfully synced commit.
	// +optional
	LastSyncedCommit string `json:"lastSyncedCommit,omitempty"`

	// lastSyncTime is when the repo was last synced.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// discoveredManifests is the number of K8s manifests discovered in the repo.
	// +optional
	DiscoveredManifests int32 `json:"discoveredManifests,omitempty"`

	// driftCount is the number of resources with config drift from the repo.
	// +optional
	DriftCount int32 `json:"driftCount,omitempty"`

	// lastError describes the most recent sync error, if any.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Branch",type=string,JSONPath=`.spec.branch`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Drifts",type=integer,JSONPath=`.status.driftCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// GitOpsRepository is the Schema for the gitopsrepositories API.
// It represents an onboarded GitOps repository for drift detection and PR-based remediation.
type GitOpsRepository struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GitOpsRepositorySpec `json:"spec"`

	// +optional
	Status GitOpsRepositoryStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GitOpsRepositoryList contains a list of GitOpsRepository
type GitOpsRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GitOpsRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitOpsRepository{}, &GitOpsRepositoryList{})
}
