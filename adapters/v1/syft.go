package v1

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
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
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/registryauth"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/opencontainers/go-digest"
	"go.opentelemetry.io/otel"
)

// formatResolvedPlatform builds an OCI-style "os/arch[/variant]" string from the platform
// fields Syft/stereoscope actually resolved an image against. Returns "" unless both os and
// architecture are known.
func formatResolvedPlatform(os, arch, variant string) string {
	if os == "" || arch == "" {
		return ""
	}
	parts := []string{os, arch}
	if variant != "" {
		parts = append(parts, variant)
	}
	return strings.Join(parts, "/")
}

// SyftAdapter implements SBOMCreator from ports using Syft's API
type SyftAdapter struct {
	maxImageSize      int64
	maxSBOMSize       int
	proxyRegistryMap  map[string]string
	pullMutex         sync.Mutex
	scanTimeout       time.Duration
	scanEmbeddedSBOMs bool
}

const digestDelim = "@"

var _ ports.SBOMCreator = (*SyftAdapter)(nil)

// NewSyftAdapter initializes the SyftAdapter struct
func NewSyftAdapter(scanTimeout time.Duration, maxImageSize int64, maxSBOMSize int, scanEmbeddedSBOMs bool, proxyRegistryMap map[string]string) *SyftAdapter {
	return &SyftAdapter{
		maxImageSize:      maxImageSize,
		maxSBOMSize:       maxSBOMSize,
		proxyRegistryMap:  proxyRegistryMap,
		scanTimeout:       scanTimeout,
		scanEmbeddedSBOMs: scanEmbeddedSBOMs,
	}
}

func rewriteImageRef(imageRef string, proxyMap map[string]string) string {
	if len(proxyMap) == 0 {
		return imageRef
	}
	keys := make([]string, 0, len(proxyMap))
	for k := range proxyMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, original := range keys {
		proxy := strings.TrimRight(proxyMap[original], "/")
		if proxy == "" {
			continue
		}
		if strings.HasPrefix(imageRef, original+"/") {
			return proxy + imageRef[len(original):]
		}
		// treat docker.io and index.docker.io as the same registry
		if original == "docker.io" && strings.HasPrefix(imageRef, "index.docker.io/") {
			return proxy + imageRef[len("index.docker.io"):]
		}
		if original == "index.docker.io" && strings.HasPrefix(imageRef, "docker.io/") {
			return proxy + imageRef[len("docker.io"):]
		}
	}
	return imageRef
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

	imgPlatform, err := parseSyftPlatform(options.Platform)
	if err != nil {
		return domainSBOM, err
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
	pullRef := rewriteImageRef(imageID, s.proxyRegistryMap)
	usedFallback := false
	src, err := syft.GetSource(ctxWithSize, pullRef, syftGetSourceConfig(&registryOptions, imgPlatform))

	if err != nil && strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		usedFallback = true
		logger.L().Debug("got MANIFEST_UNKNOWN, retrying with imageTag",
			helpers.String("imageTag", imageTag),
			helpers.String("imageID", imageID))
		pullRef = rewriteImageRef(imageTag, s.proxyRegistryMap)
		src, err = syft.GetSource(ctxWithSize, pullRef, syftGetSourceConfig(&registryOptions, imgPlatform))
	}

	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		usedFallback = true
		unauthorizedErr := err
		if provider, ok := registryauth.For(pullRef); ok {
			if creds, credErr := provider.Credentials(ctx, pullRef); credErr != nil || creds == nil {
				metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategoryRegistryAuth, provider.Strategy(), metrics.FallbackOutcomeFailed)
				logger.L().Debug("registry auth provider credentials unavailable, falling back to anonymous",
					helpers.Error(credErr),
					helpers.String("imageID", imageID))
			} else {
				registryOptions.Credentials = []image.RegistryCredentials{*creds}
				src, err = syft.GetSource(ctxWithSize, pullRef, syftGetSourceConfig(&registryOptions, imgPlatform))
				outcome := metrics.FallbackOutcomeFailed
				if err == nil {
					outcome = metrics.FallbackOutcomeSucceeded
				}
				metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategoryRegistryAuth, provider.Strategy(), outcome)
			}
		}
		// If no provider matched, its credentials were unavailable, or it succeeded in auth
		// but still got 401, fall back to anonymous access. err/src retain the last attempt.
		if err != nil {
			logger.L().Debug("retrying without credentials",
				helpers.String("imageID", imageID))
			registryOptions.Credentials = nil
			src, err = syft.GetSource(ctxWithSize, pullRef, syftGetSourceConfig(&registryOptions, imgPlatform))
			outcome := metrics.FallbackOutcomeFailed
			if err == nil {
				outcome = metrics.FallbackOutcomeSucceeded
			}
			metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategoryRegistryAuth, metrics.FallbackStrategyAnonymous, outcome)
			if err != nil && !strings.Contains(err.Error(), "401 Unauthorized") {
				err = fmt.Errorf("%w (anonymous fallback failed: %v)", unauthorizedErr, err)
			}
		}
	}

	metrics.RecordSourceResolution(ctx, metrics.ComponentInProcess, usedFallback, err == nil)

	switch {
	case err != nil && (errors.Is(err, image.ErrImageTooLarge) || strings.Contains(err.Error(), image.ErrImageTooLarge.Error())):
		metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyImageTooLarge, metrics.FallbackOutcomeClassified)
		logger.L().Ctx(ctx).Warning("Image exceeds size limit",
			helpers.Int("maxImageSize", int(s.maxImageSize)),
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.TooLarge
		domainSBOM.Annotations[domain.StatusReasonAnnotationKey] = domain.ReasonImageTooLarge
		domainSBOM.Annotations[domain.MaxImageSizeAnnotationKey] = fmt.Sprintf("%d", s.maxImageSize)
		return domainSBOM, nil
	case err != nil && strings.Contains(err.Error(), "401 Unauthorized"):
		domainSBOM.Status = helpersv1.Unauthorize
		return domainSBOM, err
	case err != nil:
		// Requested-but-unavailable platforms surface here as *image.ErrPlatformMismatch
		// (from stereoscope, once it has positively resolved the image but its OS/arch don't
		// match options.Platform). Propagated as-is: classifySBOMError in core/services
		// recognizes it via errors.As and reports a distinct "platform not found" reason
		// instead of the generic SBOM-generation-failed fallback (see #512).
		var platformErr *image.ErrPlatformMismatch
		if errors.As(err, &platformErr) {
			metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategoryPlatform, metrics.FallbackStrategyPlatformMismatch, metrics.FallbackOutcomeFailed)
		}
		return domainSBOM, err
	}

	// record the platform actually resolved, whether it was explicitly requested or left for
	// Syft to pick, so a silently-wrong-arch SBOM is inspectable after the fact (see #512).
	if meta, ok := src.Describe().Metadata.(source.ImageMetadata); ok {
		if resolved := formatResolvedPlatform(meta.OS, meta.Architecture, meta.Variant); resolved != "" {
			domainSBOM.Annotations[domain.ResolvedPlatformAnnotationKey] = resolved
		}
	}

	// generate SBOM
	// use a deadline to prevent the process from hanging for too long
	var syftSBOM *sbom.SBOM
	// ensure no parallel pulls
	s.pullMutex.Lock()
	defer s.pullMutex.Unlock()
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
		cfg := syft.DefaultCreateSBOMConfig()
		cfg.ToolName = "syft"
		cfg.ToolVersion = s.Version()
		cfg = cfg.WithCatalogerSelection(
			cataloging.NewSelectionRequest().WithRemovals(
				"file-digest-cataloger",
				"file-metadata-cataloger",
				"file-executable-cataloger",
			),
		)
		if s.scanEmbeddedSBOMs {
			// ask Syft to also scan the image for embedded SBOMs
			cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
		}
		syftSBOM, err = syft.CreateSBOM(context.Background(), src, cfg)
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}
		return nil
	})
	switch {
	case errors.Is(err, deadline.ErrTimedOut):
		metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyIncomplete, metrics.FallbackOutcomeClassified)
		logger.L().Ctx(ctx).Warning("Syft timed out",
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, nil
	case err == nil:
		// continue
	default:
		metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyIncomplete, metrics.FallbackOutcomeClassified)
		// also mark as incomplete if we failed to extract packages
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, err
	}

	// strip the SBOM to reduce size
	v1beta1.StripSBOM(syftSBOM)
	// check the size of the SBOM. This is necessarily a post-hoc check: Syft doesn't expose
	// an incremental/streaming size hook to check maxSBOMSize during cataloging, only once
	// syft.CreateSBOM above has already returned a complete result (see #473 and the
	// maxSBOMSize caveat in docs/CONFIGURATION.md). Memory used while generating is bounded
	// by the process's memory limit, not by maxSBOMSize.
	sz := size.Of(syftSBOM)
	domainSBOM.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", sz)
	if sz > s.maxSBOMSize {
		metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategySBOMTooLarge, metrics.FallbackOutcomeClassified)
		logger.L().Ctx(ctx).Warning("SBOM exceeds size limit",
			helpers.Int("maxImageSize", s.maxSBOMSize),
			helpers.Int("size", sz),
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.TooLarge
		domainSBOM.Annotations[domain.StatusReasonAnnotationKey] = domain.ReasonSBOMTooLarge
		domainSBOM.Annotations[domain.MaxSBOMSizeAnnotationKey] = fmt.Sprintf("%d", s.maxSBOMSize)
		return domainSBOM, nil
	}

	// mark SBOM as ready
	domainSBOM.Status = helpersv1.Learning

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

// Version returns Syft's version which is used to tag SBOMs
func (s *SyftAdapter) Version() string {
	v := tools.PackageVersion("github.com/anchore/syft")
	// no more processing needed
	return v
}

func (s *SyftAdapter) GetMaxImageSize() int64 {
	return s.maxImageSize
}

func (s *SyftAdapter) GetMaxSBOMSize() int {
	return s.maxSBOMSize
}

func (s *SyftAdapter) GetMemoryLimit() string {
	return ""
}
