package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
)

// CVERepository is the port implemented by adapters to be used in ScanService to store CVE manifests
type CVERepository interface {
	GetCVE(ctx context.Context, name, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (domain.CVEManifest, error)
	StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error
	StoreCVESummary(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error
}

// SBOMRepository is the port implemented by adapters to be used in ScanService to store SBOMs
type SBOMRepository interface {
	GetSBOM(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error)
	GetSBOMp(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error)
	StoreSBOM(ctx context.Context, sbom domain.SBOM) error
}
