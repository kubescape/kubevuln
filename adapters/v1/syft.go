package v1

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/eapache/go-resiliency/deadline"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	containerregistryV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
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
		ID:                 imageID,
		SBOMCreatorVersion: s.Version(),
		Annotations: map[string]string{
			instanceidhandler.ImageTagMetadataKey: imageID,
		},
		Labels: tools.LabelsFromImageID(imageID),
	}
	// translate business models into Syft models
	if options.Platform == "" {
		options.Platform = runtime.GOARCH
	}
	sourceInput, err := source.ParseInput(imageID, options.Platform)
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
	registryOptions := image.RegistryOptions{
		InsecureSkipTLSVerify: options.InsecureSkipTLSVerify,
		InsecureUseHTTP:       options.InsecureUseHTTP,
		Credentials:           credentials,
		Platform:              options.Platform,
	}
	// prepare temporary directory for image download
	t := file.NewTempDirGenerator("stereoscope")
	defer func(t *file.TempDirGenerator) {
		err := t.Cleanup()
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to cleanup temp dir", helpers.String("imageID", imageID), helpers.Error(err))
		}
	}(t)
	// download image
	// TODO check ephemeral storage usage and see if we can kill the goroutine
	logger.L().Debug("downloading image", helpers.String("imageID", imageID))
	src, err := newFromRegistry(ctx, t, sourceInput, registryOptions)
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
		logger.L().Debug("extracting packages", helpers.String("imageID", imageID))
		catalogOptions := cataloger.Config{
			Search:      cataloger.DefaultSearchConfig(),
			Parallelism: 4, // TODO assess this value
		}
		pkgCatalog, relationships, actualDistro, err = syft.CatalogPackages(&src, catalogOptions)
		return err
	})
	switch err {
	case deadline.ErrTimedOut:
		logger.L().Ctx(ctx).Warning("Syft timed out", helpers.String("imageID", imageID))
		domainSBOM.Status = domain.SBOMStatusTimedOut
		return domainSBOM, nil
	case nil:
		// continue
	default:
		return domainSBOM, err
	}
	// generate SBOM
	logger.L().Debug("generating SBOM", helpers.String("imageID", imageID))
	syftSBOM := sbom.SBOM{
		Source:        src.Metadata,
		Relationships: relationships,
		Artifacts: sbom.Artifacts{
			PackageCatalog:    pkgCatalog,
			LinuxDistribution: actualDistro,
		},
	}
	// convert SBOM
	logger.L().Debug("converting SBOM", helpers.String("imageID", imageID))
	domainSBOM.Content, err = s.syftToDomain(syftSBOM)
	// return SBOM
	logger.L().Debug("returning SBOM", helpers.String("imageID", imageID))
	return domainSBOM, err
}

func newFromRegistry(ctx context.Context, t *file.TempDirGenerator, sourceInput *source.Input, registryOptions image.RegistryOptions) (source.Source, error) {
	imageTempDir, err := t.NewDirectory("oci-registry-image")
	if err != nil {
		return source.Source{}, err
	}
	// download image
	ref, err := name.ParseReference(sourceInput.UserInput, prepareReferenceOptions(registryOptions)...)
	if err != nil {
		return source.Source{}, fmt.Errorf("unable to parse registry reference=%q: %+v", sourceInput.UserInput, err)
	}
	platform, err := image.NewPlatform(registryOptions.Platform)
	if err != nil {
		return source.Source{}, fmt.Errorf("unable to create platform reference=%q: %+v", sourceInput.UserInput, err)
	}
	descriptor, err := remote.Get(ref, prepareRemoteOptions(ctx, ref, registryOptions, platform)...)
	if err != nil {
		return source.Source{}, fmt.Errorf("failed to get image descriptor from registry: %+v", err)
	}

	imgRemote, err := descriptor.Image()
	if err != nil {
		return source.Source{}, fmt.Errorf("failed to get image from registry: %+v", err)
	}

	// craft a repo digest from the registry reference and the known digest
	// note: the descriptor is fetched from the registry, and the descriptor digest is the same as the repo digest
	repoDigest := fmt.Sprintf("%s/%s@%s", ref.Context().RegistryStr(), ref.Context().RepositoryStr(), descriptor.Digest.String())

	metadata := []image.AdditionalMetadata{
		image.WithRepoDigests(repoDigest),
	}

	// make a best effort to get the manifest, should not block getting an image though if it fails
	if manifestBytes, err := imgRemote.RawManifest(); err == nil {
		metadata = append(metadata, image.WithManifest(manifestBytes))
	}

	if platform != nil {
		metadata = append(metadata,
			image.WithArchitecture(platform.Architecture, platform.Variant),
			image.WithOS(platform.OS),
		)
	}

	img := image.New(imgRemote, t, imageTempDir, metadata...)

	err = img.Read()
	if err != nil {
		return source.Source{}, fmt.Errorf("could not read image: %+v", err)
	}

	src, err := source.NewFromImageWithName(img, sourceInput.Location, sourceInput.Name)
	if err != nil {
		return source.Source{}, fmt.Errorf("could not populate source with image: %w", err)
	}
	return src, nil
}

func prepareReferenceOptions(registryOptions image.RegistryOptions) []name.Option {
	var options []name.Option
	if registryOptions.InsecureUseHTTP {
		options = append(options, name.Insecure)
	}
	return options
}

func prepareRemoteOptions(ctx context.Context, ref name.Reference, registryOptions image.RegistryOptions, p *image.Platform) (options []remote.Option) {
	options = append(options, remote.WithContext(ctx))

	if registryOptions.InsecureSkipTLSVerify {
		t := &http.Transport{
			//nolint: gosec
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		options = append(options, remote.WithTransport(t))
	}

	if p != nil {
		options = append(options, remote.WithPlatform(containerregistryV1.Platform{
			Architecture: p.Architecture,
			OS:           p.OS,
			Variant:      p.Variant,
		}))
	}

	// note: the authn.Authenticator and authn.Keychain options are mutually exclusive, only one may be provided.
	// If no explicit authenticator can be found, then fallback to the keychain.
	authenticator := registryOptions.Authenticator(ref.Context().RegistryStr())
	if authenticator != nil {
		options = append(options, remote.WithAuth(authenticator))
	} else {
		// use the Keychain specified from a docker config file.
		logger.L().Debug("no registry credentials configured, using the default keychain")
		options = append(options, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	return options
}

// Version returns Syft's version which is used to tag SBOMs
func (s *SyftAdapter) Version() string {
	return tools.PackageVersion("github.com/anchore/syft")
}
