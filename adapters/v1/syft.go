package v1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/eapache/go-resiliency/deadline"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/hashicorp/go-multierror"
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
		Name:               name,
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
	}

	syftOpts := defaultPackagesOptions()

	// prepare temporary directory for image download
	t := file.NewTempDirGenerator("stereoscope")
	defer func(t *file.TempDirGenerator) {
		err := t.Cleanup()
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to cleanup temp dir", helpers.Error(err),
				helpers.String("imageID", imageID))
		}
	}(t)

	// download image
	logger.L().Debug("downloading image",
		helpers.String("imageID", imageID))
	src, err := detectSource(imageID, syftOpts, &registryOptions)

	// check for 401 error and retry without credentials
	var transportError *transport.Error
	if errors.As(err, &transportError) && transportError.StatusCode == http.StatusUnauthorized {
		logger.L().Debug("got 401, retrying without credentials",
			helpers.String("imageID", imageID))
		registryOptions.Credentials = nil
		src, err = detectSource(imageID, syftOpts, &registryOptions)
	}
	switch {
	case errors.Is(err, ErrImageTooLarge):
		logger.L().Ctx(ctx).Warning("Image exceeds size limit",
			helpers.Int("maxImageSize", int(s.maxImageSize)),
			helpers.String("imageID", imageID))
		domainSBOM.Status = instanceidhandler.Incomplete
		return domainSBOM, nil
	case err != nil:
		return domainSBOM, err
	}

	// generate SBOM
	// use a deadline to prevent the process from hanging for too long
	// TODO check memory usage and see if we can kill the goroutine
	var syftSBOM *sbom.SBOM
	dl := deadline.New(s.scanTimeout)
	err = dl.Run(func(stopper <-chan struct{}) error {
		// generate SBOM
		logger.L().Debug("generating SBOM",
			helpers.String("imageID", imageID))
		syftSBOM, err = generateSBOM(name, s.Version(), src, &syftOpts.Catalog)
		return err
	})
	switch err {
	case deadline.ErrTimedOut:
		logger.L().Ctx(ctx).Warning("Syft timed out",
			helpers.String("imageID", imageID))
		domainSBOM.Status = instanceidhandler.Incomplete
		return domainSBOM, nil
	case nil:
		// continue
	default:
		// also mark as incomplete if we failed to extract packages
		domainSBOM.Status = instanceidhandler.Incomplete
		return domainSBOM, err
	}

	// convert SBOM
	logger.L().Debug("converting SBOM",
		helpers.String("imageID", imageID))
	domainSBOM.Content, err = s.syftToDomain(syftSBOM)

	// return SBOM
	logger.L().Debug("returning SBOM",
		helpers.String("imageID", imageID),
		helpers.Int("packages", len(domainSBOM.Content.Artifacts)))
	return domainSBOM, err
}

type packagesOptions struct {
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	options.Catalog     `yaml:",inline" mapstructure:",squash"`
}

func defaultPackagesOptions() *packagesOptions {
	defaultCatalogOpts := options.DefaultCatalog()

	// TODO(matthyx): assess this value
	defaultCatalogOpts.Parallelism = 4

	return &packagesOptions{
		Output:      options.DefaultOutput(),
		UpdateCheck: options.DefaultUpdateCheck(),
		Catalog:     defaultCatalogOpts,
	}
}

func detectSource(userInput string, opts *packagesOptions, registryOptions *image.RegistryOptions) (source.Source, error) {
	detection, err := source.Detect(
		userInput,
		source.DetectConfig{
			DefaultImageSource: opts.DefaultImagePullSource,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("could not deteremine source: %w", err)
	}

	var platform *image.Platform

	if opts.Platform != "" {
		platform, err = image.NewPlatform(opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("invalid platform: %w", err)
		}
	}

	hashers, err := Hashers(opts.Source.File.Digests...)
	if err != nil {
		return nil, fmt.Errorf("invalid hash: %w", err)
	}

	src, err := detection.NewSource(
		source.DetectionSourceConfig{
			Alias: source.Alias{
				Name:    opts.Source.Name,
				Version: opts.Source.Version,
			},
			RegistryOptions: registryOptions,
			Platform:        platform,
			Exclude: source.ExcludeConfig{
				Paths: opts.Exclusions,
			},
			DigestAlgorithms: hashers,
			BasePath:         opts.BasePath,
		},
	)

	return src, nil
}

func generateSBOM(toolName string, toolVersion string, src source.Source, opts *options.Catalog) (*sbom.SBOM, error) {
	tasks, err := eventloop.Tasks(opts)
	if err != nil {
		return nil, err
	}

	s := sbom.SBOM{
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:          toolName,
			Version:       toolVersion,
			Configuration: opts,
		},
	}

	err = buildRelationships(&s, src, tasks)

	return &s, err
}

func buildRelationships(s *sbom.SBOM, src source.Source, tasks []eventloop.Task) error {
	var errs error

	var relationships []<-chan artifact.Relationship
	for _, task := range tasks {
		c := make(chan artifact.Relationship)
		relationships = append(relationships, c)
		go func(task eventloop.Task) {
			err := eventloop.RunTask(task, &s.Artifacts, src, c)
			if err != nil {
				errs = multierror.Append(errs, err)
			}
		}(task)
	}

	s.Relationships = append(s.Relationships, mergeRelationships(relationships...)...)

	return errs
}

func mergeRelationships(cs ...<-chan artifact.Relationship) (relationships []artifact.Relationship) {
	for _, c := range cs {
		for n := range c {
			relationships = append(relationships, n)
		}
	}

	return relationships
}

// Version returns Syft's version which is used to tag SBOMs
func (s *SyftAdapter) Version() string {
	return tools.PackageVersion("github.com/anchore/syft")
}
