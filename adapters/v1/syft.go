package v1

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/syft"
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
	maxImageSize int64
	scanTimeout  time.Duration
}

var _ ports.SBOMCreator = (*SyftAdapter)(nil)

// NewSyftAdapter initializes the SyftAdapter struct
func NewSyftAdapter(scanTimeout time.Duration, maxImageSize int64) *SyftAdapter {
	return &SyftAdapter{
		maxImageSize: maxImageSize,
		scanTimeout:  scanTimeout,
	}
}

// CreateSBOM creates an SBOM for a given imageID, restrict parallelism to prevent disk space issues,
// a timeout prevents the process from hanging for too long.
// Format is syft JSON and the resulting SBOM is tagged with the Syft version.
func (s *SyftAdapter) CreateSBOM(ctx context.Context, name, imageID string, options domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "SyftAdapter.CreateSBOM")
	defer span.End()

	// prepare an SBOM and fill it progressively
	domainSBOM := domain.SBOM{
		Name:               name,
		SBOMCreatorVersion: s.Version(),
		SBOMCreatorName:    "syft",
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey: imageID,
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
		MaxImageSize:          s.maxImageSize,
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
	logger.L().Debug("downloading image", helpers.String("imageID", imageID))

	// TODO: support maxImageSize
	// @matthyx: I removed the support for maxImageSize because it's not supported by Syft, it looks like you developed the image download mechanism, I want to find a better solution.
	src, err := detectSource(imageID, syftOpts, &registryOptions)

	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		logger.L().Debug("got 401, retrying without credentials",
			helpers.String("imageID", imageID))
		registryOptions.Credentials = nil
		src, err = detectSource(imageID, syftOpts, &registryOptions)
	}
	switch {
	case errors.Is(err, image.ErrImageTooLarge):
		logger.L().Ctx(ctx).Warning("Image exceeds size limit",
			helpers.Int("maxImageSize", int(s.maxImageSize)),
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, nil
	case err != nil && strings.Contains(err.Error(), "401 Unauthorized"):
		domainSBOM.Status = helpersv1.Unauthorize
		return domainSBOM, err
	case err != nil:
		return domainSBOM, err
	}

	// generate SBOM
	// use a deadline to prevent the process from hanging for too long
	// TODO check memory usage and see if we can kill the goroutine
	var syftSBOM *sbom.SBOM
	dl := deadline.New(s.scanTimeout)
	err = dl.Run(func(stopper <-chan struct{}) error {
		// make sure we clean the temp dir
		defer func(src source.Source) {
			if err := src.Close(); err != nil {
				logger.L().Ctx(ctx).Warning("failed to close source", helpers.Error(err),
					helpers.String("imageID", imageID))
			}
		}(src)
		// generate SBOM
		logger.L().Debug("generating SBOM",
			helpers.String("imageID", imageID))
		id := clio.Identification{
			Name:    name,
			Version: s.Version(),
		}
		syftSBOM, err = syft.CreateSBOM(ctx, src, syftOpts.Catalog.ToSBOMConfig(id))
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}
		return nil
	})
	switch err {
	case deadline.ErrTimedOut:
		logger.L().Ctx(ctx).Warning("Syft timed out",
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, nil
	case nil:
		// continue
	default:
		// also mark as incomplete if we failed to extract packages
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, err
	}

	// mark SBOM as ready
	domainSBOM.Status = helpersv1.Ready

	// convert SBOM
	logger.L().Debug("converting SBOM",
		helpers.String("imageID", imageID))
	domainSBOM.Content, err = s.syftToDomain(*syftSBOM)

	// return SBOM
	logger.L().Debug("returning SBOM",
		helpers.String("imageID", imageID),
		helpers.Int("packages", len(domainSBOM.Content.Artifacts)))
	return domainSBOM, err
}

type packagesOptions struct {
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.Config      `yaml:",inline" mapstructure:",squash"`
	options.Catalog     `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
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
	var err error
	var platform *image.Platform

	if opts.Platform != "" {
		platform, err = image.NewPlatform(opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("invalid platform: %w", err)
		}
	}

	src, err := source.NewFromStereoscopeImage(
		source.StereoscopeImageConfig{
			Alias: source.Alias{
				Name:    opts.Source.Name,
				Version: opts.Source.Version,
			},
			RegistryOptions: registryOptions,
			Platform:        platform,
			Exclude: source.ExcludeConfig{
				Paths: opts.Exclusions,
			},
			Reference: userInput,
			From:      image.DetermineDefaultImagePullSource(userInput),
		},
	)

	return src, err
}

// Version returns Syft's version which is used to tag SBOMs
func (s *SyftAdapter) Version() string {
	return tools.PackageVersion("github.com/anchore/syft")
}
