package v1

import (
	"bytes"
	"context"
	"sync"

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

type SyftAdapter struct {
	mu sync.Mutex
}

var _ ports.SBOMCreator = (*SyftAdapter)(nil)

func NewSyftAdapter() *SyftAdapter {
	return &SyftAdapter{}
}

func (s *SyftAdapter) CreateSBOM(ctx context.Context, imageID string, options domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "CreateSBOM")
	defer span.End()
	// ensure only one SBOM is created at a time
	s.mu.Lock()
	defer s.mu.Unlock()
	// translate business models in syft models
	userInput := "registry:" + imageID
	sourceInput, err := source.ParseInput(userInput, "", true)
	if err != nil {
		panic(err)
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
		panic(err)
	}
	// extract packages
	catalogOptions := cataloger.Config{
		Search: cataloger.DefaultSearchConfig(),
	}
	pkgCatalog, relationships, actualDistro, err := syft.CatalogPackages(src, catalogOptions)
	if err != nil {
		panic(err)
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

func (s *SyftAdapter) Version() string {
	// TODO implement me
	return "TODO"
}
