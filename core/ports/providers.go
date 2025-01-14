package ports

import (
	"context"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/k8s-interface/instanceidhandler"
	"github.com/kubescape/kubevuln/core/domain"
)

// CVEScanner is the port implemented by adapters to be used in ScanService to generate CVE manifests
type CVEScanner interface {
	DBVersion(ctx context.Context) string
	Ready(ctx context.Context) bool
	ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error)
	Version() string
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

type ContainerRelevancyScan struct {
	ContainerName    string
	ImageID          string
	ImageTag         string
	InstanceID       instanceidhandler.IInstanceID
	InstanceIDString string
	Labels           map[string]string
	RelevantFiles    mapset.Set[string]
	Wlid             string
}

// Relevancy is the port implemented by adapters to be used in ScanService to calculate filtered SBOMs
type Relevancy interface {
	GetContainerRelevancyScans(ctx context.Context, namespace, name string) ([]ContainerRelevancyScan, error)
}
