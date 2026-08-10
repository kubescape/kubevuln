package domain

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	CriticalSeverity   = "Critical"
	HighSeverity       = "High"
	MediumSeverity     = "Medium"
	LowSeverity        = "Low"
	NegligibleSeverity = "Negligible"
	UnknownSeverity    = "Unknown"
)

type CVEExceptions []armotypes.VulnerabilityExceptionPolicy

// ExceptionStats reports counts computed while resolving a scan's CVE exceptions from
// SecurityException/ClusterSecurityException CRDs, so a caller holding a metrics recorder
// (core/services.ScanService) can turn them into Prometheus signals without the conversion
// and platform-adapter code in adapters/v1 needing any dependency on the metrics package.
// See GetCVEExceptions (core/ports.Platform) and ConvertToVulnerabilityExceptionPolicies.
type ExceptionStats struct {
	// ExpiredBySource counts SecurityException/ClusterSecurityException CRDs skipped this
	// call because their spec.expiresAt has passed, keyed by "SecurityException" or
	// "ClusterSecurityException".
	ExpiredBySource map[string]int
}

// CVEManifest contains a JSON CVE report manifest with some metadata
type CVEManifest struct {
	Content            *v1beta1.GrypeDocument
	Annotations        map[string]string
	Labels             map[string]string
	Name               string
	Wlid               string
	SBOMCreatorName    string
	SBOMCreatorVersion string
	CVEScannerName     string
	CVEScannerVersion  string
	CVEDBVersion       string
}
