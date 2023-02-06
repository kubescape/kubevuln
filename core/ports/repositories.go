package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
)

type CVERepository interface {
	GetCVE(ctx context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVE, err error)
	StoreCVE(ctx context.Context, cve domain.CVE) error
}

type SBOMRepository interface {
	GetSBOM(ctx context.Context, imageID, SBOMCreatorVersion string) (sbom domain.SBOM, err error)
	GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (sbom domain.SBOM, err error)
	StoreSBOM(ctx context.Context, sbom domain.SBOM) error
}
