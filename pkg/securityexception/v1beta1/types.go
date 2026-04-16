package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecurityException defines a namespaced exception for vulnerability and posture findings.
type SecurityException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SecurityExceptionSpec `json:"spec,omitempty"`
}

// SecurityExceptionList is a list of SecurityException resources.
type SecurityExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []SecurityException `json:"items"`
}

// ClusterSecurityException defines a cluster-scoped exception for vulnerability and posture findings.
type ClusterSecurityException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SecurityExceptionSpec `json:"spec,omitempty"`
}

// ClusterSecurityExceptionList is a list of ClusterSecurityException resources.
type ClusterSecurityExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterSecurityException `json:"items"`
}

// VulnerabilityStatus is the VEX status of a vulnerability exception.
type VulnerabilityStatus string

const (
	VulnerabilityStatusNotAffected        VulnerabilityStatus = "not_affected"
	VulnerabilityStatusFixed              VulnerabilityStatus = "fixed"
	VulnerabilityStatusUnderInvestigation VulnerabilityStatus = "under_investigation"
)

// PostureAction is the action to take for a posture exception.
type PostureAction string

const (
	PostureActionIgnore    PostureAction = "ignore"
	PostureActionAlertOnly PostureAction = "alert_only"
)

// SecurityExceptionSpec defines the desired state of a SecurityException.
type SecurityExceptionSpec struct {
	Author          string                   `json:"author,omitempty"`
	Reason          string                   `json:"reason,omitempty"`
	ExpiresAt       *metav1.Time             `json:"expiresAt,omitempty"`
	Match           ExceptionMatch           `json:"match,omitempty"`
	Vulnerabilities []VulnerabilityException `json:"vulnerabilities,omitempty"`
	Posture         []PostureException       `json:"posture,omitempty"`
}

// ExceptionMatch defines which workloads the exception applies to.
type ExceptionMatch struct {
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	ObjectSelector    *metav1.LabelSelector `json:"objectSelector,omitempty"`
	Resources         []ResourceMatch       `json:"resources,omitempty"`
	Images            []string              `json:"images,omitempty"`
}

// ResourceMatch identifies a workload by kind and optional name.
type ResourceMatch struct {
	APIGroup string `json:"apiGroup,omitempty"`
	Kind     string `json:"kind"`
	Name     string `json:"name,omitempty"`
}

// VulnerabilityException defines an exception for a specific CVE.
type VulnerabilityException struct {
	Vulnerability   VulnerabilityRef    `json:"vulnerability"`
	Status          VulnerabilityStatus `json:"status"`
	Justification   string              `json:"justification,omitempty"`
	ImpactStatement string              `json:"impactStatement,omitempty"`
	ExpiredOnFix    bool                `json:"expiredOnFix,omitempty"`
}

// VulnerabilityRef identifies a vulnerability by CVE ID.
type VulnerabilityRef struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
}

// PostureException defines an exception for a posture control.
type PostureException struct {
	ControlID     string        `json:"controlID"`
	FrameworkName string        `json:"frameworkName,omitempty"`
	Action        PostureAction `json:"action"`
}
