package v1

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
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
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
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
	maxImageSize int64
	scanTimeout  time.Duration
}

var _ ports.SBOMCreator = (*SyftAdapter)(nil)
var ErrImageTooLarge = fmt.Errorf("image size exceeds maximum allowed size")

// NewSyftAdapter initializes the SyftAdapter struct
func NewSyftAdapter(scanTimeout time.Duration, maxImageSize int64) *SyftAdapter {
	return &SyftAdapter{
		maxImageSize: maxImageSize,
		scanTimeout:  scanTimeout,
	}
}

// CreateSBOM creates an SBOM for a given imageID, restrict parallelism to prevent disk space issues,
// a timeout prevents the process from hanging for too long.
// Format is SPDX JSON and the resulting SBOM is tagged with the Syft version.
func (s *SyftAdapter) CreateSBOM(ctx context.Context, name, imageID string, options domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "SyftAdapter.CreateSBOM")
	defer span.End()
	// prepare an SBOM and fill it progressively
	domainSBOM := domain.SBOM{
		ID:                 name,
		SBOMCreatorVersion: s.Version(),
		Annotations: map[string]string{
			instanceidhandler.ImageIDMetadataKey: imageID,
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
	logger.L().Debug("downloading image", helpers.String("imageID", imageID))
	src, err := newFromRegistry(t, sourceInput, registryOptions, s.maxImageSize)
	// check for 401 error and retry without credentials
	var transportError *transport.Error
	if errors.As(err, &transportError) && transportError.StatusCode == http.StatusUnauthorized {
		logger.L().Debug("got 401, retrying without credentials", helpers.String("imageID", imageID))
		registryOptions.Credentials = nil
		src, err = newFromRegistry(t, sourceInput, registryOptions, s.maxImageSize)
	}
	switch {
	case errors.Is(err, ErrImageTooLarge):
		logger.L().Ctx(ctx).Warning("Image exceeds size limit", helpers.Int("maxImageSize", int(s.maxImageSize)), helpers.String("imageID", imageID))
		domainSBOM.Status = instanceidhandler.Incomplete
		return domainSBOM, nil
	case err != nil:
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
		domainSBOM.Status = instanceidhandler.Incomplete
		return domainSBOM, nil
	case nil:
		// continue
	default:
		// also mark as incomplete if we failed to extract packages
		domainSBOM.Status = instanceidhandler.Incomplete
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

func newFromRegistry(t *file.TempDirGenerator, sourceInput *source.Input, registryOptions image.RegistryOptions, maxImageSize int64) (source.Source, error) {
	imageTempDir, err := t.NewDirectory("oci-registry-image")
	if err != nil {
		return source.Source{}, err
	}
	// download image
	ref, err := name.ParseReference(sourceInput.UserInput, prepareReferenceOptions(registryOptions)...)
	if err != nil {
		return source.Source{}, fmt.Errorf("unable to parse registry reference=%q: %w", sourceInput.UserInput, err)
	}
	platform, err := image.NewPlatform(registryOptions.Platform)
	if err != nil {
		return source.Source{}, fmt.Errorf("unable to create platform reference=%q: %w", sourceInput.UserInput, err)
	}
	descriptor, err := remote.Get(ref, prepareRemoteOptions(ref, registryOptions, platform)...)
	if err != nil {
		return source.Source{}, fmt.Errorf("failed to get image descriptor from registry: %w", err)
	}

	imgRemote, err := descriptor.Image()
	if err != nil {
		return source.Source{}, fmt.Errorf("failed to get image from registry: %w", err)
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

	err = read(img, imgRemote, imageTempDir, maxImageSize)
	if err != nil {
		return source.Source{}, fmt.Errorf("could not read image: %w", err)
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

func prepareRemoteOptions(ref name.Reference, registryOptions image.RegistryOptions, p *image.Platform) (options []remote.Option) {
	options = append(options, remote.WithContext(context.TODO()))

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

func read(i *image.Image, imgRemote containerregistryV1.Image, imageTempDir string, maxImageSize int64) error {
	var layers = make([]*image.Layer, 0)
	var err error
	i.Metadata, err = readImageMetadata(imgRemote)
	if err != nil {
		return err
	}

	v1Layers, err := imgRemote.Layers()
	if err != nil {
		return err
	}

	fileCatalog := image.NewFileCatalog()

	for idx, v1Layer := range v1Layers {
		layer := image.NewLayer(v1Layer)
		err := layer.Read(fileCatalog, i.Metadata, idx, imageTempDir)
		if err != nil {
			return err
		}
		i.Metadata.Size += layer.Metadata.Size
		// unfortunately we cannot check the size before we gunzip the layer
		if i.Metadata.Size > maxImageSize {
			return ErrImageTooLarge
		}
		layers = append(layers, layer)
	}

	i.Layers = layers

	// in order to resolve symlinks all squashed trees must be available
	err = squash(i, fileCatalog)

	i.FileCatalog = fileCatalog
	i.SquashedSearchContext = filetree.NewSearchContext(i.SquashedTree(), i.FileCatalog)

	return err
}

func readImageMetadata(img containerregistryV1.Image) (image.Metadata, error) {
	id, err := img.ConfigName()
	if err != nil {
		return image.Metadata{}, err
	}

	config, err := img.ConfigFile()
	if err != nil {
		return image.Metadata{}, err
	}

	mediaType, err := img.MediaType()
	if err != nil {
		return image.Metadata{}, err
	}

	rawConfig, err := img.RawConfigFile()
	if err != nil {
		return image.Metadata{}, err
	}

	return image.Metadata{
		ID:        id.String(),
		Config:    *config,
		MediaType: mediaType,
		RawConfig: rawConfig,
	}, nil
}

func squash(i *image.Image, catalog *image.FileCatalog) error {
	var lastSquashTree filetree.ReadWriter

	for idx, layer := range i.Layers {
		if idx == 0 {
			lastSquashTree = layer.Tree.(filetree.ReadWriter)
			layer.SquashedTree = layer.Tree
			layer.SquashedSearchContext = filetree.NewSearchContext(layer.SquashedTree, catalog.Index)
			continue
		}

		var unionTree = filetree.NewUnionFileTree()
		unionTree.PushTree(lastSquashTree)
		unionTree.PushTree(layer.Tree.(filetree.ReadWriter))

		squashedTree, err := unionTree.Squash()
		if err != nil {
			return fmt.Errorf("failed to squash tree %d: %w", idx, err)
		}

		layer.SquashedTree = squashedTree
		layer.SquashedSearchContext = filetree.NewSearchContext(layer.SquashedTree, catalog.Index)
		lastSquashTree = squashedTree
	}
	return nil
}

// Version returns Syft's version which is used to tag SBOMs
func (s *SyftAdapter) Version() string {
	return tools.PackageVersion("github.com/anchore/syft")
}
