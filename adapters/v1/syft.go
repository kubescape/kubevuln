package v1

import (
	"bytes"
	"context"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/eapache/go-resiliency/deadline"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"go.opentelemetry.io/otel"
)

// SyftAdapter implements SBOMCreator from ports using Syft's API
type SyftAdapter struct {
	scanTimeout time.Duration
}

var _ ports.SBOMCreator = (*SyftAdapter)(nil)

// NewSyftAdapter initializes the SyftAdapter struct
func NewSyftAdapter(scanTimeout time.Duration) *SyftAdapter {
	return &SyftAdapter{
		scanTimeout: scanTimeout,
	}
}

// CreateSBOM creates an SBOM for a given imageID, restrict parallelism to prevent disk space issues,
// a timeout prevents the process from hanging for too long.
// Format is SPDX JSON and the resulting SBOM is tagged with the Syft version.
func (s *SyftAdapter) CreateSBOM(ctx context.Context, imageID string, options domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "SyftAdapter.CreateSBOM")
	defer span.End()
	// prepare an SBOM and fill it progressively
	domainSBOM := domain.SBOM{
		ImageID:            imageID,
		SBOMCreatorVersion: s.Version(ctx),
	}
	// translate business models into Syft models
	userInput := "registry:" + imageID
	sourceInput, err := source.ParseInput(userInput, "", true)
	if err != nil {
		return domainSBOM, err
	}
	credentials := make([]image.RegistryCredentials, len(options.Credentials))
	for i, v := range options.Credentials {
		credentials[i] = image.RegistryCredentials{
			Authority: v.Authority,
			Username:  v.Username,
			Password:  v.Password,
			Token:     v.Token,
		}
	}
	registryOptions := &image.RegistryOptions{
		InsecureSkipTLSVerify: options.InsecureSkipTLSVerify,
		InsecureUseHTTP:       options.InsecureUseHTTP,
		Credentials:           credentials,
		Platform:              options.Platform,
	}
	// download image
	// TODO check ephemeral storage usage and see if we can kill the goroutine
	logger.L().Debug("downloading image")
	src, cleanup, err := source.New(*sourceInput, registryOptions, []string{})
	defer cleanup()
	if err != nil {
		return domainSBOM, err
	}
	// extract packages
	// use a deadline to prevent the process from hanging for too long
	// TODO check memory usage and see if we can kill the goroutine
	var pkgCatalog *pkg.Catalog
	var relationships []artifact.Relationship
	var actualDistro *linux.Release
	dl := deadline.New(s.scanTimeout)
	err = dl.Run(func(stopper <-chan struct{}) error {
		logger.L().Debug("extracting packages")
		catalogOptions := cataloger.Config{
			Search:      cataloger.DefaultSearchConfig(),
			Parallelism: 4, // TODO assess this value
		}
		pkgCatalog, relationships, actualDistro, err = syft.CatalogPackages(src, catalogOptions)
		return err
	})
	switch err {
	case deadline.ErrTimedOut:
		logger.L().Ctx(ctx).Warning("Syft timed out", helpers.String("imageID", imageID))
		domainSBOM.Status = domain.SBOMStatusTimedOut
	case nil:
		// continue
	default:
		return domainSBOM, err
	}
	// generate SBOM
	logger.L().Debug("generating SBOM")
	syftSbom := sbom.SBOM{
		Source:        src.Metadata,
		Relationships: relationships,
		Artifacts: sbom.Artifacts{
			PackageCatalog:    pkgCatalog,
			LinuxDistribution: actualDistro,
		},
	}
	var buf bytes.Buffer
	err = spdxjson.Format().Encode(&buf, syftSbom)
	if err != nil {
		return domainSBOM, err
	}
	domainSBOM.Content = buf.Bytes()
	// return SBOM
	logger.L().Debug("returning SBOM")
	return domainSBOM, nil
}

// Version returns Syft's version which is used to tag SBOMs
func (s *SyftAdapter) Version(ctx context.Context) string {
	ctx, span := otel.Tracer("").Start(ctx, "SyftAdapter.Version")
	defer span.End()
	return tools.PackageVersion("github.com/anchore/syft")
}
