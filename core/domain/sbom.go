package domain

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	StatusReasonAnnotationKey       = "kubescape.io/status-reason"
	MaxImageSizeAnnotationKey       = "kubescape.io/max-image-size"
	MaxSBOMSizeAnnotationKey        = "kubescape.io/max-sbom-size"
	ScannerMemoryLimitAnnotationKey = "kubescape.io/scanner-memory-limit"
	// ResolvedPlatformAnnotationKey records the OCI platform ("os/arch[/variant]") that was
	// actually used to resolve the scanned image, regardless of whether the caller requested
	// one explicitly (RegistryOptions.Platform) or left it empty and let the adapter fall back
	// to whatever the image manifest provides. Set by both SBOM adapters on success so a
	// silently-wrong-arch SBOM is inspectable after the fact (see #512).
	ResolvedPlatformAnnotationKey = "kubescape.io/resolved-platform"

	ReasonImageTooLarge    = "image-too-large"
	ReasonSBOMTooLarge     = "sbom-too-large"
	ReasonScannerOOM       = "scanner-oom"
	ReasonTooManyRequests  = "too-many-requests"
	ReasonPlatformNotFound = "platform-not-found"
)

// SBOM contains an syft SBOM in JSON format with some metadata
type SBOM struct {
	Content            *v1beta1.SyftDocument
	Annotations        map[string]string
	Labels             map[string]string
	Name               string
	SBOMCreatorName    string
	SBOMCreatorVersion string
	Status             string
}

// RegistryCredentials contains OCI registry credentials required for connection
// it is closely related to the Stereoscope image.RegistryCredentials struct
type RegistryCredentials struct {
	Authority string
	Username  string
	Password  string
	Token     string
}

// RegistryOptions contains OCI registry configuration parameters required for connection
// it is closely related to the Stereoscope image.RegistryOptions struct used by Grype
type RegistryOptions struct {
	Platform              string
	Credentials           []RegistryCredentials
	InsecureSkipTLSVerify bool
	InsecureUseHTTP       bool
}
