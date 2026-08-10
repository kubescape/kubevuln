package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VEXSource defines a namespaced source for external VEX documents.
type VEXSource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VEXSourceSpec   `json:"spec,omitempty"`
	Status VEXSourceStatus `json:"status,omitempty"`
}

// VEXSourceList is a list of VEXSource resources.
type VEXSourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []VEXSource `json:"items"`
}

// VEXFormat is the format of the external VEX feed.
type VEXFormat string

const (
	VEXFormatOpenVEX VEXFormat = "OpenVEX"
	VEXFormatCSAF    VEXFormat = "CSAF"
)

// VEXSourceSpec defines the desired configuration of a VEXSource.
type VEXSourceSpec struct {
	URL             string          `json:"url"`
	Format          VEXFormat       `json:"format"`
	RefreshInterval string          `json:"refreshInterval"` // e.g. "12h" or "10m"
	ImageScope      ImageScopeRules `json:"imageScope,omitempty"`
}

// ImageScopeRules specifies which images the VEX applies to.
type ImageScopeRules struct {
	MatchExpressions []MatchExpression `json:"matchExpressions,omitempty"`
}

// MatchExpression defines a single matching rule for the image scope.
type MatchExpression struct {
	Key      string   `json:"key"`              // e.g. "image.repository" or "image.registry"
	Operator string   `json:"operator"`         // "StartsWith" | "In" | "Exists"
	Values   []string `json:"values,omitempty"` // Argument array for the operator
}

// VEXSourceStatus defines the observed state of a VEXSource.
type VEXSourceStatus struct {
	Conditions             []metav1.Condition `json:"conditions,omitempty"`
	LastFetchedTime        *metav1.Time       `json:"lastFetchedTime,omitempty"`
	IngestedStatementCount int                `json:"ingestedStatementCount,omitempty"`
}
