package v1

import (
	"bytes"
	"context"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

// SyftAdapter implements SBOMCreator from ports using Syft's API
type SyftAdapter struct {
}

var _ ports.SBOMCreator = (*SyftAdapter)(nil)

// NewSyftAdapter initializes the SyftAdapter struct
func NewSyftAdapter() *SyftAdapter {
	return &SyftAdapter{}
}

// CreateSBOM creates an SBOM for a given imageID, only one scan happens at a time to prevent disk space issues
// format is SPDX JSON and the resulting SBOM is tagged with the Syft version
func (s *SyftAdapter) CreateSBOM(ctx context.Context, imageID string, options domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "CreateSBOM")
	defer span.End()
	// translate business models into Syft models
	userInput := "registry:" + imageID
	sourceInput, err := source.ParseInput(userInput, "", true)
	if err != nil {
		return domain.SBOM{}, err
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
	src, cleanup, err := source.New(*sourceInput, registryOptions, []string{})
	defer cleanup()
	if err != nil {
		return domain.SBOM{}, err
	}
	// extract packages
	catalogOptions := cataloger.Config{
		Search: cataloger.DefaultSearchConfig(),
	}
	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(src, catalogOptions)
	if err != nil {
		return domain.SBOM{}, err
	}
	// generate SBOM
	syftSbom := sbom.SBOM{
		Source:        src.Metadata,
		Relationships: relationships,
		Artifacts: sbom.Artifacts{
			PackageCatalog:    pkgCatalog,
			LinuxDistribution: actualDistro,
		},
	}
	// return SBOM
	var buf bytes.Buffer
	err = spdxjson.Format().Encode(&buf, syftSbom)
	if err != nil {
		return domain.SBOM{}, err
	}
	return domain.SBOM{
		ImageID:            imageID,
		SBOMCreatorVersion: s.Version(),
		Content:            buf.Bytes(),
	}, nil
}

// Version returns Syft's version which is used to tag SBOMs
// it should be filled-in at build time as Go no longer reflects on its packages at runtime
func (s *SyftAdapter) Version() string {
	// TODO implement me
	return "TODO"
}
