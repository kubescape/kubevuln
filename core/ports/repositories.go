package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
)

// CVERepository is the port implemented by adapters to be used in ScanService to store CVE manifests
type CVERepository interface {
	GetCVE(ctx context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVEManifest, err error)
	StoreCVE(ctx context.Context, cve domain.CVEManifest) error
}

// SBOMRepository is the port implemented by adapters to be used in ScanService to store SBOMs
type SBOMRepository interface {
	GetSBOM(ctx context.Context, imageID, SBOMCreatorVersion string) (sbom domain.SBOM, err error)
	GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (sbom domain.SBOM, err error)
	StoreSBOM(ctx context.Context, sbom domain.SBOM) error
}
