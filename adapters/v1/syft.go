package v1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/eapache/go-resiliency/deadline"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/opencontainers/go-digest"
	"go.opentelemetry.io/otel"
)

// SyftAdapter implements SBOMCreator from ports using Syft's API
type SyftAdapter struct {
	maxImageSize      int64
	maxSBOMSize       int
	pullMutex         sync.Mutex
	scanTimeout       time.Duration
	scanEmbeddedSBOMs bool
	diveAdapter       *DiveAdapter
}

const digestDelim = "@"

var _ ports.SBOMCreator = (*SyftAdapter)(nil)

// NewSyftAdapter initializes the SyftAdapter struct
func NewSyftAdapter(scanTimeout time.Duration, maxImageSize int64, maxSBOMSize int, scanEmbeddedSBOMs bool) *SyftAdapter {
	return &SyftAdapter{
		maxImageSize:      maxImageSize,
		maxSBOMSize:       maxSBOMSize,
		scanTimeout:       scanTimeout,
		scanEmbeddedSBOMs: scanEmbeddedSBOMs,
		diveAdapter:       NewDiveAdapter("", scanTimeout),
	}
}

func NormalizeImageID(imageID, imageTag string) string {
	// registry scanning doesn't provide imageID, so we use imageTag as a reference
	if imageID == "" {
		return imageTag
	}

	// try to parse imageID as a full digest
	if newDigest, err := name.NewDigest(imageID); err == nil {
		return newDigest.String()
	}
	// if it's not a full digest, we need to use imageTag as a reference
	tag, err := name.ParseReference(imageTag)
	if err != nil {
		return ""
	}

	// and append imageID as a digest
	parts := strings.Split(imageID, digestDelim)
	// filter garbage
	if len(parts) > 1 {
		imageID = parts[len(parts)-1]
	}
	prefix := digest.Canonical.String() + ":"
	if !strings.HasPrefix(imageID, prefix) {
		// add missing prefix
		imageID = prefix + imageID
	}
	// we don't validate the digest, assuming it's correct
	return tag.Context().String() + "@" + imageID
}

// CreateSBOM creates an SBOM for a given imageID, restrict parallelism to prevent disk space issues,
// a timeout prevents the process from hanging for too long.
// Format is syft JSON and the resulting SBOM is tagged with the Syft version.
func (s *SyftAdapter) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "SyftAdapter.CreateSBOM")
	defer span.End()

	if imageTag != "" {
		imageID = NormalizeImageID(imageID, imageTag)
	}
	// prepare an SBOM and fill it progressively
	domainSBOM := domain.SBOM{
		Name:               name,
		SBOMCreatorVersion: s.Version(),
		SBOMCreatorName:    "syft",
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:     imageID,
			helpersv1.ToolVersionMetadataKey: s.Version(),
		},
		Labels: tools.LabelsFromImageID(imageID),
	}
	domainSBOM.Annotations[helpersv1.ImageTagMetadataKey] = imageTag

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

	ctxWithSize := context.WithValue(context.Background(), image.MaxImageSize, s.maxImageSize)
	src, err := syft.GetSource(ctxWithSize, imageID, syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithSources("registry"))

	if err != nil && strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		logger.L().Debug("got MANIFEST_UNKNOWN, retrying with imageTag",
			helpers.String("imageTag", imageTag),
			helpers.String("imageID", imageID))
		src, err = syft.GetSource(ctxWithSize, imageTag, syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithSources("registry"))
	}

	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		logger.L().Debug("got 401, retrying without credentials",
			helpers.String("imageID", imageID))
		registryOptions.Credentials = nil
		src, err = syft.GetSource(ctxWithSize, imageID, syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithSources("registry"))
	}

	switch {
	case err != nil && strings.Contains(err.Error(), image.ErrImageTooLarge.Error()):
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
	// ensure no parallel pulls
	s.pullMutex.Lock()
	defer s.pullMutex.Unlock()
	dl := deadline.New(s.scanTimeout)
	err = dl.Run(func(stopper <-chan struct{}) error {
		// make sure we clean the temp dir
		defer func(src source.Source) {
			if err := src.Close(); err != nil {
				logger.L().Ctx(ctx).Fatal("failed to close source", helpers.Error(err),
					helpers.String("imageID", imageID))
			}
		}(src)
		// generate SBOM
		logger.L().Debug("generating SBOM",
			helpers.String("imageID", imageID))
		cfg := syft.DefaultCreateSBOMConfig()
		cfg.ToolName = name
		cfg.ToolVersion = s.Version()
		if s.scanEmbeddedSBOMs {
			// ask Syft to also scan the image for embedded SBOMs
			cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
		}
		syftSBOM, err = syft.CreateSBOM(ctx, src, cfg)
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}
		return nil
	})
	switch {
	case errors.Is(err, deadline.ErrTimedOut):
		logger.L().Ctx(ctx).Warning("Syft timed out",
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, nil
	case err == nil:
		// continue
	default:
		// also mark as incomplete if we failed to extract packages
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, err
	}

	// check the size of the SBOM
	sz := size.Of(syftSBOM)
	domainSBOM.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", sz)
	if sz > s.maxSBOMSize {
		logger.L().Ctx(ctx).Warning("SBOM exceeds size limit",
			helpers.Int("maxImageSize", s.maxSBOMSize),
			helpers.Int("size", sz),
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.TooLarge
		return domainSBOM, nil
	}

	// mark SBOM as ready
	domainSBOM.Status = helpersv1.Ready

	// convert SBOM
	logger.L().Debug("converting SBOM",
		helpers.String("imageID", imageID))
	domainSBOM.Content, err = s.syftToDomain(*syftSBOM)
	if err != nil {
		return domainSBOM, err
	}

	// Run dive scan on the same image after syft has successfully processed it
	if imageTag != "" {
		go func() {
			diveCtx, cancel := context.WithTimeout(context.Background(), s.scanTimeout)
			defer cancel()

			// Generate unique output path for dive results with timestamp and job ID
			timestamp := time.Now().Format("20060102-150405")
			jobID := generateJobID(imageTag, timestamp)
			outputPath := fmt.Sprintf("./dive-results/%s-%s-%s-dive.json", name, timestamp, jobID)

			_, diveErr := s.diveAdapter.ScanImage(diveCtx, imageTag, outputPath)
			if diveErr != nil {
				logger.L().Ctx(ctx).Warning("dive scan failed",
					helpers.Error(diveErr),
					helpers.String("imageTag", imageTag))
			} else {
				logger.L().Ctx(ctx).Debug("dive scan completed successfully",
					helpers.String("imageTag", imageTag),
					helpers.String("outputPath", outputPath))
			}
		}()
	}

	// return SBOM
	logger.L().Debug("returning SBOM",
		helpers.String("imageID", imageID),
		helpers.Int("packages", len(domainSBOM.Content.Artifacts)))
	return domainSBOM, nil
}

// Version returns Syft's version which is used to tag SBOMs
func (s *SyftAdapter) Version() string {
	v := tools.PackageVersion("github.com/anchore/syft")
	// no more processing needed
	return v
}

// generateJobID creates a unique job ID based on image tag and timestamp
func generateJobID(imageTag, timestamp string) string {
	// Create a hash from image tag and timestamp to ensure uniqueness
	hash := sha256.Sum256([]byte(imageTag + timestamp))
	return hex.EncodeToString(hash[:8]) // Use first 8 characters for readability
}
