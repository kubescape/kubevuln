package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
)

// CVEScanner is the port implemented by adapters to be used in ScanService to generate CVE manifests
type CVEScanner interface {
	CreateRelevantCVE(ctx context.Context, cve, cvep domain.CVEManifest) (domain.CVEManifest, error)
	DBVersion() string
	Ready() bool
	ScanSBOM(ctx context.Context, sbom domain.SBOM, exceptions domain.CVEExceptions) (domain.CVEManifest, error)
	UpdateDB(ctx context.Context) error
	Version() string
}

// SBOMCreator is the port implemented by adapters to be used in ScanService to generate SBOM
type SBOMCreator interface {
	CreateSBOM(ctx context.Context, imageID string, options domain.RegistryOptions) (domain.SBOM, error)
	Version() string
}

// Platform is the port implemented by adapters to be used in ScanService to report scan results and send telemetry data
type Platform interface {
	GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, error)
	SendStatus(ctx context.Context, step int) error
	SubmitCVE(ctx context.Context, cve domain.CVEManifest, hasRelevancy bool) error
}
