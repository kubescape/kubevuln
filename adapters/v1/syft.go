package v1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DmitriyVTitov/size"
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
	"github.com/kubescape/kubevuln/internal/syftsource"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/opencontainers/go-digest"
	"go.opentelemetry.io/otel"
)

// createSBOMFn is an indirection over syft.CreateSBOM so the deadline handling in
// CreateSBOM can be unit-tested without cataloguing a real image.
var createSBOMFn = syft.CreateSBOM

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
		// treat docker.io and index.docker.io as the same registry, but only when the
		// spelling imageRef actually uses has no entry of its own: a configured entry for
		// that exact spelling is a more specific match (the one "longest prefix wins"
		// above already prefers) and must not be skipped in favor of the alias's proxy
		// just because the alias happens to sort first by length (#883).
		if original == "docker.io" && strings.HasPrefix(imageRef, "index.docker.io/") && !hasUsableProxy(proxyMap, "index.docker.io") {
			return proxy + imageRef[len("index.docker.io"):]
		}
		if original == "index.docker.io" && strings.HasPrefix(imageRef, "docker.io/") && !hasUsableProxy(proxyMap, "docker.io") {
			return proxy + imageRef[len("docker.io"):]
		}
	}
	return imageRef
}

// hasUsableProxy reports whether proxyMap has a non-empty (after trimming any trailing
// slash) proxy value configured for key.
func hasUsableProxy(proxyMap map[string]string, key string) bool {
	return strings.TrimRight(proxyMap[key], "/") != ""
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

	imgPlatform, err := syftsource.ParsePlatform(options.Platform)
	if err != nil {
		return domainSBOM, err
	}

	// download image
	logger.L().Debug("downloading image", helpers.String("imageID", imageID))

	ctxWithTimeout := ctx
	if s.scanTimeout > 0 {
		var cancel context.CancelFunc
		ctxWithTimeout, cancel = context.WithTimeout(ctx, s.scanTimeout)
		defer cancel()
	}

	//nolint:staticcheck // stereoscope expects string key image.MaxImageSize
	ctxWithSize := context.WithValue(ctxWithTimeout, image.MaxImageSize, s.maxImageSize)
	// ensure no parallel pulls: syft.GetSource (inside registryauth.ResolveSource) is what
	// actually downloads image layers to local disk (via stereoscope), so pullMutex must
	// guard it too, not just cataloging - otherwise a second CreateSBOM call can download a
	// full image concurrently with a still-running "abandoned" download left behind by a first
	// call that already timed out (#687).
	// Ownership of the unlock transfers to the dl.Run closure below once source resolution
	// succeeds; every early-return branch between here and there must unlock for itself.
	// The warning below is armed *before* Lock() and fired by its own timer, not checked after
	// Lock() returns: sync.Mutex.Lock never returns until the prior holder releases it, so a
	// post-acquisition check can only ever report a wait that already ended - it would stay
	// silent for the exact case it exists to catch, a previous cataloguing goroutine hung
	// indefinitely (createSBOMFn/Syft's cataloguers do not observe cancellation - see the
	// dl.Run comment below). That's an accepted tradeoff, not a bug: there is no watchdog that
	// force-releases the mutex, so a sufficiently pathological image (corrupt archive,
	// cataloguer bug, stalled local FS) can keep it held indefinitely. This log line is the
	// operator-visible signal for that case, since neither the liveness nor readiness probe
	// currently reflects it.
	var longWaitWarning *time.Timer
	if s.scanTimeout > 0 {
		longWaitWarning = time.AfterFunc(s.scanTimeout, func() {
			logger.L().Ctx(ctx).Warning("waiting unusually long to acquire pullMutex; a previous scan may be stuck",
				helpers.String("imageID", imageID))
		})
	}
	s.pullMutex.Lock()
	if longWaitWarning != nil {
		longWaitWarning.Stop()
	}
	pullMutexUnlockOnce := sync.Once{}
	unlockPullMutex := func() { pullMutexUnlockOnce.Do(s.pullMutex.Unlock) }

	// Registered before the pull, not just cataloguing: registryauth.ResolveSource below is
	// what actually creates the stereoscope temp dir and downloads image layers into it, and
	// that used to run fully unprotected against a concurrent StartPeriodicTempDirSweep pass
	// -- in this process or the sidecar's, which shares the same os.TempDir() -- deleting the
	// directory out from under a still-in-progress pull (see #796). Ownership of ending it
	// transfers to the dl.Run closure below once source resolution succeeds, the same way
	// pullMutex's unlock does; every early-return branch between here and there must end it
	// for itself.
	endTempDirUseOnce := sync.Once{}
	endTempDirUseFn := tools.BeginActiveTempDirUse(os.TempDir())
	endActiveTempDirUse := func() { endTempDirUseOnce.Do(endTempDirUseFn) }

	// The MANIFEST_UNKNOWN and 401 fallback ladder lives in internal/registryauth, shared
	// with the sidecar scanner, which ran a copy of it. The pull keeps its own context,
	// carrying the size limit; ctxWithTimeout is what bounds the credential lookup.
	src, err := registryauth.ResolveSource(ctxWithTimeout, metrics.ComponentInProcess,
		func(_ context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
			return tools.RetryWithBackoff(ctxWithSize, "source_resolution", tools.Default429RetryConfig(), tools.IsRateLimitError, func(retryCtx context.Context) (source.Source, error) {
				return syft.GetSource(retryCtx, ref, syftsource.GetSourceConfig(opts, imgPlatform))
			})
		},
		rewriteImageRef(imageID, s.proxyRegistryMap),
		rewriteImageRef(imageTag, s.proxyRegistryMap),
		registryOptions)

	switch {
	// Note: stereoscope/oci-registry wraps deadline errors in a custom error type that does not implement Unwrap(),
	// so strings.Contains check is required alongside errors.Is.
	case err != nil && (errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded")):
		metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyIncomplete, metrics.FallbackOutcomeClassified)
		logger.L().Ctx(ctx).Warning("Syft timed out during image resolution",
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.Incomplete
		endActiveTempDirUse()
		unlockPullMutex()
		return domainSBOM, nil
	case err != nil && (errors.Is(err, image.ErrImageTooLarge) || strings.Contains(err.Error(), image.ErrImageTooLarge.Error())):
		metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyImageTooLarge, metrics.FallbackOutcomeClassified)
		logger.L().Ctx(ctx).Warning("Image exceeds size limit",
			helpers.Int("maxImageSize", int(s.maxImageSize)),
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.TooLarge
		domainSBOM.Annotations[domain.StatusReasonAnnotationKey] = domain.ReasonImageTooLarge
		domainSBOM.Annotations[domain.MaxImageSizeAnnotationKey] = fmt.Sprintf("%d", s.maxImageSize)
		endActiveTempDirUse()
		unlockPullMutex()
		return domainSBOM, nil
	case err != nil && strings.Contains(err.Error(), "401 Unauthorized"):
		domainSBOM.Status = helpersv1.Unauthorize
		endActiveTempDirUse()
		unlockPullMutex()
		return domainSBOM, err
	case err != nil:
		// Requested-but-unavailable platforms surface here as *image.ErrPlatformMismatch
		// (from stereoscope, once it has positively resolved the image but its OS/arch don't
		// match options.Platform). Propagated as-is: classifySBOMError in core/services
		// recognizes it via errors.As and reports a distinct "platform not found" reason
		// instead of the generic SBOM-generation-failed fallback (see #512).
		if syftsource.IsPlatformMismatch(err) {
			metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategoryPlatform, metrics.FallbackStrategyPlatformMismatch, metrics.FallbackOutcomeFailed)
		}
		endActiveTempDirUse()
		unlockPullMutex()
		return domainSBOM, err
	}

	// record the platform actually resolved, whether it was explicitly requested or left for
	// Syft to pick, so a silently-wrong-arch SBOM is inspectable after the fact (see #512).
	if meta, ok := src.Describe().Metadata.(source.ImageMetadata); ok {
		if resolved := syftsource.FormatResolvedPlatform(meta.OS, meta.Architecture, meta.Variant); resolved != "" {
			domainSBOM.Annotations[domain.ResolvedPlatformAnnotationKey] = resolved
		}
	}

	// generate SBOM
	// use a deadline to prevent the process from hanging for too long
	var syftSBOM *sbom.SBOM
	// Buffered so a goroutine abandoned by the deadline can always publish and exit, even
	// when nobody is left to receive.
	generated := make(chan *sbom.SBOM, 1)
	// pullMutex is already held (see the Lock() before syft.GetSource above), covering source
	// resolution too. Unlock here, not via a defer at the top of CreateSBOM: this closure can
	// outlive CreateSBOM's own return (see the comment below), so unlocking when CreateSBOM
	// returns would let a subsequent CreateSBOM call start pulling/cataloging while this
	// one is still running against disk, defeating the "ensure no parallel pulls" purpose
	// of pullMutex on exactly the timeout path most likely to correlate with disk
	// pressure. Unlocking only once this closure actually finishes - promptly on success
	// or failure, late if the deadline fired first - is what makes pullMutex serialize the
	// disk-touching work itself, not just the synchronous portion of the call.
	dl := deadline.New(s.scanTimeout)
	err = dl.Run(func(stopper <-chan struct{}) error {
		defer unlockPullMutex()
		defer endActiveTempDirUse()
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
		// This closure can outlive the call: deadline.Run cannot stop its work function and
		// documents as much, and Syft's cataloguers do not observe cancellation either, so on
		// timeout it keeps running after CreateSBOM has already returned Incomplete. It must
		// therefore not touch any variable the caller reads. Keep the result local and publish
		// it on the channel, which is only received from once dl.Run reports success.
		created, createErr := tools.RetryWithBackoff(ctxWithSize, "sbom_generation", tools.Default429RetryConfig(), tools.IsRateLimitError, func(retryCtx context.Context) (*sbom.SBOM, error) {
			return createSBOMFn(retryCtx, src, cfg)
		})
		if createErr != nil {
			return fmt.Errorf("failed to generate SBOM: %w", createErr)
		}
		generated <- created
		return nil
	})
	switch {
	case errors.Is(err, deadline.ErrTimedOut) || errors.Is(err, context.DeadlineExceeded) || (err != nil && strings.Contains(err.Error(), "context deadline exceeded")):
		metrics.RecordScanFallback(ctx, metrics.ComponentInProcess, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyIncomplete, metrics.FallbackOutcomeClassified)
		logger.L().Ctx(ctx).Warning("Syft timed out",
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, nil
	case err == nil:
		// dl.Run reports success only once the work function returned nil, which it does
		// after publishing, so this receive cannot block.
		syftSBOM = <-generated
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
			helpers.Int("maxSBOMSize", s.maxSBOMSize),
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
