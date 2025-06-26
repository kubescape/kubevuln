package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Image",type="string",JSONPath=".spec.image"
//+kubebuilder:printcolumn:name="Namespace",type="string",JSONPath=".spec.namespace"
//+kubebuilder:printcolumn:name="Timestamp",type="date",JSONPath=".spec.timestamp"
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.status"

// ScanReport is the Schema for the scanreports API
type ScanReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScanReportSpec   `json:"spec,omitempty"`
	Status ScanReportStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ScanReportList contains a list of ScanReport
type ScanReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanReport `json:"items"`
}

// ScanReportSpec defines the desired state of ScanReport
type ScanReportSpec struct {
	Image       string `json:"image"`
	Namespace   string `json:"namespace"`
	Timestamp   string `json:"timestamp"`
	ClusterName string `json:"clusterName"`
	JobID       string `json:"jobID,omitempty"`

	// Complete JSON reports from each tool
	DiveReport       string `json:"diveReport,omitempty"`       // Complete dive JSON report
	TrufflehogReport string `json:"trufflehogReport,omitempty"` // Complete trufflehog JSON report

	// Report metadata
	ReportPath string                 `json:"reportPath,omitempty"`
	Reports    map[string]interface{} `json:"reports,omitempty"` // Additional reports if needed
}

// ScanReportStatus defines the observed state of ScanReport
type ScanReportStatus struct {
	Status      string `json:"status,omitempty"`
	LastUpdated string `json:"lastUpdated,omitempty"`
}

// TruffleHogResult represents a single secret found by TruffleHog
type TruffleHogResult struct {
	SourceMetadata struct {
		Data struct {
			Docker struct {
				File  string `json:"file"`
				Image string `json:"image"`
				Layer string `json:"layer"`
				Tag   string `json:"tag"`
			} `json:"Docker"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	SourceID              int         `json:"SourceID"`
	SourceType            int         `json:"SourceType"`
	SourceName            string      `json:"SourceName"`
	DetectorType          int         `json:"DetectorType"`
	DetectorName          string      `json:"DetectorName"`
	DetectorDescription   string      `json:"DetectorDescription"`
	DecoderName           string      `json:"DecoderName"`
	Verified              bool        `json:"Verified"`
	VerificationFromCache bool        `json:"VerificationFromCache"`
	Raw                   string      `json:"Raw"`
	RawV2                 string      `json:"RawV2"`
	Redacted              string      `json:"Redacted"`
	ExtraData             interface{} `json:"ExtraData"`
	StructuredData        interface{} `json:"StructuredData"`
}
