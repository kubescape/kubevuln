package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
)

type CVEScanner interface {
	CreateRelevantCVE(ctx context.Context, cve, cvep domain.CVE) (domain.CVE, error)
	DBVersion() string
	Ready() bool
	ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVE, error)
	UpdateDB(ctx context.Context) error
	Version() string
}

type SBOMCreator interface {
	CreateSBOM(ctx context.Context, imageID string, options domain.RegistryOptions) (domain.SBOM, error)
	Version() string
}

type Platform interface {
	SubmitCVE(cve domain.CVE) error
}
