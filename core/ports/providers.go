package ports

import (
	"context"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/kubevuln/core/domain"
)

// CVEScanner is the port implemented by adapters to be used in ScanService to generate CVE manifests
type CVEScanner interface {
	DBVersion(ctx context.Context) string
	Ready(ctx context.Context) bool
	ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error)
	Version(ctx context.Context) string
}

// SBOMCreator is the port implemented by adapters to be used in ScanService to generate SBOM
type SBOMCreator interface {
	CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error)
	Version() string
}

// Platform is the port implemented by adapters to be used in ScanService to report scan results and send telemetry data
type Platform interface {
	GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, error)
	ReportError(ctx context.Context, err error) error
	SendStatus(ctx context.Context, step int) error
	SubmitCVE(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest) error
}

// Relevancy is the port implemented by adapters to be used in ScanService to calculate filtered SBOMs
type Relevancy interface {
	GetRelevantFiles(ctx context.Context, namespace, name, container string) (mapset.Set[string], map[string]string, error)
}
