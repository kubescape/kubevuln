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
	VulnerabilityStatusAffected           VulnerabilityStatus = "affected"
	VulnerabilityStatusFixed              VulnerabilityStatus = "fixed"
	VulnerabilityStatusUnderInvestigation VulnerabilityStatus = "under_investigation"
)

// VulnerabilityResponse is a typed action taken or planned in response to a vulnerability
// that is real and applies. It answers "what are we doing about it", which is a separate
// question from the status "where does it stand", and has no OpenVEX equivalent: the values
// are aligned with CycloneDX VEX analysis.response[].
type VulnerabilityResponse string

const (
	VulnerabilityResponseCanNotFix           VulnerabilityResponse = "can_not_fix"
	VulnerabilityResponseWillNotFix          VulnerabilityResponse = "will_not_fix"
	VulnerabilityResponseUpdate              VulnerabilityResponse = "update"
	VulnerabilityResponseRollback            VulnerabilityResponse = "rollback"
	VulnerabilityResponseWorkaroundAvailable VulnerabilityResponse = "workaround_available"
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
	// ExpiresAt overrides the document-level spec.expiresAt for this entry only.
	// When unset, the entry inherits the document-level value.
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
	// ActionStatement describes what is being done about a vulnerability that is real and
	// applies. It maps to OpenVEX action_statement, which the spec requires for every
	// affected statement, and is the counterpart to ImpactStatement on the not_affected path.
	ActionStatement string `json:"actionStatement,omitempty"`
	// Response carries the typed actions taken or planned for an affected vulnerability.
	// It is always optional and layers on top of ActionStatement rather than replacing it.
	Response []VulnerabilityResponse `json:"response,omitempty"`
	// Subcomponents scopes the exception to specific packages within the matched
	// product, as PURLs. Semantics follow OpenVEX statements[].products[].subcomponents[]:
	// an unversioned PURL matches any version, a version-qualified PURL matches only
	// that version. When empty, the exception applies at product scope.
	Subcomponents []string `json:"subcomponents,omitempty"`
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
