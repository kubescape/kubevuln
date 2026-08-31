package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/eapache/go-resiliency/deadline"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/registryauth"
	"github.com/kubescape/kubevuln/internal/syftmeta"
	"github.com/kubescape/kubevuln/internal/syftsource"
	"github.com/kubescape/kubevuln/internal/tools"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// createSBOMFn is an indirection over syft.CreateSBOM so the deadline handling in
// CreateSBOM can be unit-tested without cataloguing a real image.
var createSBOMFn = syft.CreateSBOM

// sourceGetter abstracts the syft.GetSource call so the fallback ordering in
// resolveSource is testable with a scripted implementation.
type sourceGetter func(ctx context.Context, ref string, opts *image.RegistryOptions) (source.Source, error)

// resolveSource downloads an image source, applying the MANIFEST_UNKNOWN and
// 401/provider/anonymous fallbacks in order. It mirrors the retry chain in
// adapters/v1/syft.go so the sidecar and in-process adapters behave the same.
func resolveSource(ctx context.Context, get sourceGetter, imageID, imageTag string, opts image.RegistryOptions) (source.Source, error) {
	return registryauth.ResolveSource(ctx, metrics.ComponentSidecar,
		registryauth.Getter[source.Source](get), imageID, imageTag, opts)
}

type scannerServer struct {
	pb.UnimplementedSBOMScannerServer
	version string
}

// NewScannerServer creates a new gRPC scanner server.
func NewScannerServer() pb.SBOMScannerServer {
	return &scannerServer{
		version: tools.PackageVersion("github.com/anchore/syft"),
	}
}

// CreateSBOM handles one scan per call, with no state shared across concurrent calls: each
// invocation downloads into its own temp dir (managed internally by stereoscope) and builds
// its own SBOM from its own source. s.version is set once in NewScannerServer and never
// mutated, so it's safe to read concurrently without a lock. Do not add a mutex/semaphore
// around this method — a previous version serialized the whole RPC (pull + generation) behind
// a single process-wide lock, which defeated the caller's scanConcurrency entirely regardless
// of its configured value (see #473); the number of concurrent in-flight RPCs is bounded by
// the caller instead, matching scanConcurrency.
//
// That bound is on in-flight RPCs, not on actual Syft resource usage: syft.CreateSBOM below
// runs on context.Background() and Syft's catalogers don't support cancellation, so when
// dl.Run times out and this RPC returns Incomplete, the abandoned Syft goroutine can keep
// consuming CPU/memory in the background after the caller already considers that slot free
// and starts another scan. scanConcurrency therefore bounds concurrent requests, not peak
// concurrent Syft memory/CPU use, on this path.
func (s *scannerServer) CreateSBOM(ctx context.Context, req *pb.CreateSBOMRequest) (*pb.CreateSBOMResponse, error) {
	// imageID is already the final, normalized pull reference. The SidecarSBOMAdapter
	// normalizes it (NormalizeImageID) before sending the request - that is the single
	// normalization point. Do not normalize again here: re-normalizing an
	// already-complete reference corrupts it (e.g. into repo@sha256:<tag> when no
	// digest is known, which then fails to parse).
	imageID := req.ImageId
	imageTag := req.ImageTag

	// Parse platform for multi-arch image resolution.
	// The platform specifier uses OCI format: "os/arch[/variant]" (e.g. "linux/amd64").
	// If only an architecture is provided (e.g. "amd64"), we prepend "linux/".
	//
	// Only request a specific platform when the caller explicitly asked for one; otherwise
	// leave imgPlatform nil so Syft resolves whatever platform the image manifest provides.
	// This mirrors the in-process adapter (adapters/v1/syft.go) and matters for pod-less scan
	// paths (registry rescans, periodic CRD-based rescans) that have no node context to derive
	// a platform from: defaulting to runtime.GOARCH here used to force a platform mismatch for
	// single-arch images that don't happen to match the sidecar container's own arch (see #512).
	imgPlatform, err := syftsource.ParsePlatform(req.Platform)
	if err != nil {
		return nil, fmt.Errorf("invalid platform %q: %w", req.Platform, err)
	}

	// Build registry credentials
	credentials := make([]image.RegistryCredentials, len(req.Credentials))
	for i, c := range req.Credentials {
		credentials[i] = image.RegistryCredentials{
			Authority: c.Authority,
			Username:  c.Username,
			Password:  c.Password,
			Token:     c.Token,
		}
	}
	registryOptions := image.RegistryOptions{
		InsecureSkipTLSVerify: req.InsecureSkipTlsVerify,
		InsecureUseHTTP:       req.InsecureUseHttp,
		Credentials:           credentials,
	}

	// timeout bounds both the pull below and SBOM generation further down, as two independent
	// windows (not one budget split across both) - matching adapters/v1/syft.go's scanTimeout,
	// which bounds its own pull and cataloging phases the same way.
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	// Download image from registry, bounded by timeout: a registry that accepts a connection
	// but then stalls (no error, just no timely response) used to hang this call - and the
	// caller's scanConcurrency slot with it - indefinitely, since neither the request ctx nor
	// any deadline reached this pull; the only deadline in this method wrapped generation,
	// which starts after the pull already returned. See #742.
	logger.L().Debug("downloading image", helpers.String("imageID", imageID))
	ctxWithTimeout, cancelPull := context.WithTimeout(ctx, timeout)
	defer cancelPull()

	// Registered before the pull, not just cataloguing: resolveSource below is what actually
	// creates the stereoscope temp dir and downloads image layers into it, and that used to
	// run fully unprotected against a concurrent StartPeriodicTempDirSweep pass -- in this
	// process or the in-process adapter's, which shares the same os.TempDir() -- deleting the
	// directory out from under a still-in-progress pull (see #796). Ownership of ending it
	// transfers to the dl.Run closure below once source resolution succeeds; every early-return
	// branch between here and there must end it for itself.
	endTempDirUseOnce := sync.Once{}
	endTempDirUseFn := tools.BeginActiveTempDirUse(os.TempDir())
	endActiveTempDirUse := func() { endTempDirUseOnce.Do(endTempDirUseFn) }

	src, err := resolveSource(ctxWithTimeout, func(_ context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
		return tools.RetryWithBackoff(ctxWithTimeout, "source_resolution", tools.Default429RetryConfig(), tools.IsRateLimitError, func(retryCtx context.Context) (source.Source, error) {
			ctxWithSize := context.WithValue(retryCtx, image.MaxImageSize, req.MaxImageSize) //nolint:staticcheck // stereoscope requires string context key
			return syft.GetSource(ctxWithSize, ref, syftsource.GetSourceConfig(opts, imgPlatform))
		})
	}, imageID, imageTag, registryOptions)

	switch {
	// stereoscope/oci-registry wraps deadline errors in a custom error type that does not
	// implement Unwrap(), so the strings.Contains check is required alongside errors.Is (same
	// as adapters/v1/syft.go's identical check on its own pull timeout).
	case err != nil && (errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded")):
		metrics.RecordScanFallback(ctx, metrics.ComponentSidecar, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyIncomplete, metrics.FallbackOutcomeClassified)
		logger.L().Warning("image pull timed out", helpers.String("imageID", imageID))
		endActiveTempDirUse()
		return &pb.CreateSBOMResponse{
			Status: helpersv1.Incomplete,
		}, nil
	case err != nil && (errors.Is(err, image.ErrImageTooLarge) || strings.Contains(err.Error(), image.ErrImageTooLarge.Error())):
		metrics.RecordScanFallback(ctx, metrics.ComponentSidecar, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyImageTooLarge, metrics.FallbackOutcomeClassified)
		logger.L().Warning("Image exceeds size limit",
			helpers.Int("maxImageSize", int(req.MaxImageSize)),
			helpers.String("imageID", imageID))
		endActiveTempDirUse()
		return &pb.CreateSBOMResponse{
			Status:       helpersv1.TooLarge,
			StatusReason: domain.ReasonImageTooLarge,
		}, nil
	case err != nil && strings.Contains(err.Error(), "401 Unauthorized"):
		endActiveTempDirUse()
		return &pb.CreateSBOMResponse{
			Status:       helpersv1.Unauthorize,
			ErrorMessage: err.Error(),
		}, nil
	case err != nil && syftsource.IsPlatformMismatch(err):
		metrics.RecordScanFallback(ctx, metrics.ComponentSidecar, metrics.FallbackCategoryPlatform, metrics.FallbackStrategyPlatformMismatch, metrics.FallbackOutcomeFailed)
		// The requested platform doesn't exist in the image's manifest. StatusReason travels
		// over gRPC as a plain string; the caller's classifySBOMError also recognizes the
		// "mismatched platform" text in ErrorMessage directly, so this is reported as a
		// distinct reason rather than falling into the generic SBOM-generation-failed path
		// (see #512).
		logger.L().Warning("requested platform not found in image manifest",
			helpers.String("platform", req.Platform),
			helpers.String("imageID", imageID),
			helpers.Error(err))
		endActiveTempDirUse()
		return &pb.CreateSBOMResponse{
			ErrorMessage: err.Error(),
			StatusReason: domain.ReasonPlatformNotFound,
		}, nil
	case err != nil && tools.IsRateLimitError(err):
		// StatusReason travels over gRPC as a plain string, so the caller (adapters/v1
		// SidecarSBOMAdapter.CreateSBOM) reconstructs a *transport.Error from it to keep
		// ScanService.checkCreateSBOM's errors.As(...) check working the same way it does
		// for the in-process syft adapter.
		endActiveTempDirUse()
		return &pb.CreateSBOMResponse{
			ErrorMessage: err.Error(),
			StatusReason: domain.ReasonTooManyRequests,
		}, nil
	case err != nil:
		// No syftsource.IsPlatformMismatch check here: the arm above already claims every such error,
		// so a copy of it in this arm can never run. Anything reaching here has no more
		// specific classification than "SBOM generation failed".
		endActiveTempDirUse()
		return &pb.CreateSBOMResponse{
			ErrorMessage: err.Error(),
		}, nil
	}

	// Record the platform actually resolved, whether it was explicitly requested or left for
	// Syft to pick, so a silently-wrong-arch SBOM is inspectable after the fact (see #512).
	var resolvedPlatform string
	if meta, ok := src.Describe().Metadata.(source.ImageMetadata); ok {
		resolvedPlatform = syftsource.FormatResolvedPlatform(meta.OS, meta.Architecture, meta.Variant)
	}

	// Generate SBOM with timeout (reuses the same timeout duration computed above for the
	// pull, as its own independent window).
	var syftSBOM *sbom.SBOM
	dl := deadline.New(timeout)
	// Buffered so the abandoned goroutine below can always publish and exit, even when
	// nobody is left to receive.
	generated := make(chan *sbom.SBOM, 1)
	err = dl.Run(func(stopper <-chan struct{}) error {
		defer endActiveTempDirUse()
		defer func(src source.Source) {
			if err := src.Close(); err != nil {
				logger.L().Warning("failed to close source", helpers.Error(err),
					helpers.String("imageID", imageID))
			}
		}(src)

		logger.L().Debug("generating SBOM", helpers.String("imageID", imageID))
		cfg := syft.DefaultCreateSBOMConfig()
		cfg.ToolName = "syft"
		cfg.ToolVersion = s.version
		if req.EnableEmbeddedSboms {
			cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(
				sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
		}
		// NOTE: Syft's cataloguers do not support context cancellation (see
		// https://github.com/anchore/syft/issues/3705). The deadline.Run wrapper
		// will return ErrTimedOut, but the Syft goroutine may continue until it
		// finishes naturally. This is an accepted tradeoff, the sidecar's memory
		// limit will OOM-kill the container if resource usage grows unbounded.
		//
		// Because this goroutine outlives the timeout, it must not touch any variable
		// the handler reads. It keeps its result local and publishes it on a channel,
		// which the handler only receives from once dl.Run has reported success.
		created, createErr := tools.RetryWithBackoff(context.Background(), "sbom_generation", tools.Default429RetryConfig(), tools.IsRateLimitError, func(retryCtx context.Context) (*sbom.SBOM, error) {
			return createSBOMFn(retryCtx, src, cfg)
		})
		if createErr != nil {
			return fmt.Errorf("failed to generate SBOM: %w", createErr)
		}
		generated <- created
		return nil
	})

	switch {
	case errors.Is(err, deadline.ErrTimedOut):
		metrics.RecordScanFallback(ctx, metrics.ComponentSidecar, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyIncomplete, metrics.FallbackOutcomeClassified)
		logger.L().Warning("Syft timed out", helpers.String("imageID", imageID))
		return &pb.CreateSBOMResponse{
			Status:           helpersv1.Incomplete,
			ResolvedPlatform: resolvedPlatform,
		}, nil
	case err != nil && tools.IsRateLimitError(err):
		return &pb.CreateSBOMResponse{
			ErrorMessage:     err.Error(),
			StatusReason:     domain.ReasonTooManyRequests,
			ResolvedPlatform: resolvedPlatform,
		}, nil
	case err == nil:
		// dl.Run only reports success once the work function returned nil, which it does
		// after publishing, so this receive cannot block.
		syftSBOM = <-generated
	default:
		metrics.RecordScanFallback(ctx, metrics.ComponentSidecar, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategyIncomplete, metrics.FallbackOutcomeClassified)
		return &pb.CreateSBOMResponse{
			Status:           helpersv1.Incomplete,
			ErrorMessage:     err.Error(),
			ResolvedPlatform: resolvedPlatform,
		}, nil
	}

	// Strip the SBOM to reduce size
	v1beta1.StripSBOM(syftSBOM)

	// Check in-memory size. This is necessarily a post-hoc check: Syft doesn't expose an
	// incremental/streaming size hook to check MaxSbomSize during cataloging, only once
	// syft.CreateSBOM above has already returned a complete result (see #473 and the
	// maxSBOMSize caveat in docs/CONFIGURATION.md). Memory used while generating is bounded
	// by the scanner container's memory limit, not by MaxSbomSize.
	sz := size.Of(syftSBOM)
	if sz > int(req.MaxSbomSize) {
		metrics.RecordScanFallback(ctx, metrics.ComponentSidecar, metrics.FallbackCategorySizeClassification, metrics.FallbackStrategySBOMTooLarge, metrics.FallbackOutcomeClassified)
		logger.L().Warning("SBOM exceeds size limit",
			helpers.Int("maxSBOMSize", int(req.MaxSbomSize)),
			helpers.Int("size", sz),
			helpers.String("imageID", imageID))
		return &pb.CreateSBOMResponse{
			Status:           helpersv1.TooLarge,
			SbomSize:         int64(sz),
			StatusReason:     domain.ReasonSBOMTooLarge,
			ResolvedPlatform: resolvedPlatform,
		}, nil
	}

	// Convert to SyftDocument and serialize
	doc, err := syftmeta.ToDomain(*syftSBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SBOM: %w", err)
	}
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SBOM: %w", err)
	}

	logger.L().Info("SBOM scan completed",
		helpers.String("imageID", imageID),
		helpers.Int("sbomSize", len(docBytes)),
		helpers.Int("packages", len(doc.Artifacts)))

	return &pb.CreateSBOMResponse{
		Status:           helpersv1.Learning,
		SbomDocument:     docBytes,
		SbomSize:         int64(sz),
		ResolvedPlatform: resolvedPlatform,
	}, nil
}

func (s *scannerServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Version: s.version,
		Ready:   true,
	}, nil
}
