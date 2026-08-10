package v1

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
	"golang.org/x/sync/singleflight"
)

const (
	maxCrashRetries = 3
	// retryCountTTL bounds how long a crashed image's retry count is remembered. Without
	// this, an image that crashes the scanner once or twice and is then never scanned
	// again (common with CI-generated unique tags/digests) would leave a permanent entry
	// in retryCount, since the map was previously only ever cleared on success or once
	// maxCrashRetries was hit (see #473).
	retryCountTTL = 1 * time.Hour
)

// crashRetry tracks a per-image crash-retry count and when it was last touched, so stale
// entries (images that crashed once and were never retried) can be evicted.
type crashRetry struct {
	count    int
	lastSeen time.Time
}

// SidecarSBOMAdapter implements ports.SBOMCreator by delegating SBOM generation
// to the sbom-scanner sidecar container via gRPC over a Unix domain socket.
type SidecarSBOMAdapter struct {
	client            sbomscanner.SBOMScannerClient
	maxImageSize      int64
	maxSBOMSize       int
	proxyRegistryMap  map[string]string
	scanTimeout       time.Duration
	scanEmbeddedSBOMs bool
	memoryLimit       string

	mu         sync.Mutex
	retryCount map[string]*crashRetry

	versionMu    sync.Mutex
	versionStr   string
	versionGroup singleflight.Group
}

var _ ports.SBOMCreator = (*SidecarSBOMAdapter)(nil)

// NewSidecarSBOMAdapter creates a new adapter that delegates to the sidecar scanner.
func NewSidecarSBOMAdapter(
	client sbomscanner.SBOMScannerClient,
	scanTimeout time.Duration,
	maxImageSize int64,
	maxSBOMSize int,
	scanEmbeddedSBOMs bool,
	memoryLimit string,
	proxyRegistryMap map[string]string,
) *SidecarSBOMAdapter {
	return &SidecarSBOMAdapter{
		client:            client,
		maxImageSize:      maxImageSize,
		maxSBOMSize:       maxSBOMSize,
		proxyRegistryMap:  proxyRegistryMap,
		scanTimeout:       scanTimeout,
		scanEmbeddedSBOMs: scanEmbeddedSBOMs,
		memoryLimit:       memoryLimit,
		retryCount:        make(map[string]*crashRetry),
	}
}

func (s *SidecarSBOMAdapter) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	// Normalize image ID for consistent naming
	if imageTag != "" {
		imageID = NormalizeImageID(imageID, imageTag)
	}

	// Resolved once and reused for both fields below: two separate s.Version() calls could
	// otherwise observe different results (e.g. the first hits a transient Health() failure
	// and returns "unknown" while a concurrent call succeeds moments later), tagging the same
	// SBOM with two different creator versions.
	version := s.Version()
	domainSBOM := domain.SBOM{
		Name:               name,
		SBOMCreatorVersion: version,
		SBOMCreatorName:    "syft",
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:     imageID,
			helpersv1.ToolVersionMetadataKey: version,
		},
		Labels: tools.LabelsFromImageID(imageID),
	}
	domainSBOM.Annotations[helpersv1.ImageTagMetadataKey] = imageTag

	pullImageID := rewriteImageRef(imageID, s.proxyRegistryMap)
	pullImageTag := rewriteImageRef(imageTag, s.proxyRegistryMap)

	req := sbomscanner.ScanRequest{
		ImageID:             pullImageID,
		ImageTag:            pullImageTag,
		Options:             options,
		MaxImageSize:        s.maxImageSize,
		MaxSBOMSize:         int32(s.maxSBOMSize),
		EnableEmbeddedSBOMs: s.scanEmbeddedSBOMs,
		Timeout:             s.scanTimeout,
	}

	result, err := s.client.CreateSBOM(ctx, req)
	if err != nil {
		if errors.Is(err, sbomscanner.ErrScannerCrashed) {
			return s.handleCrash(ctx, name, imageID, imageTag, options, domainSBOM, err)
		}
		return domainSBOM, err
	}

	// Map response status to domain SBOM
	domainSBOM.Status = result.Status
	domainSBOM.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", result.SBOMSize)
	if result.ResolvedPlatform != "" {
		domainSBOM.Annotations[domain.ResolvedPlatformAnnotationKey] = result.ResolvedPlatform
	}

	if result.Status == helpersv1.TooLarge {
		if result.StatusReason != "" {
			domainSBOM.Annotations[domain.StatusReasonAnnotationKey] = result.StatusReason
			if result.StatusReason == domain.ReasonImageTooLarge {
				domainSBOM.Annotations[domain.MaxImageSizeAnnotationKey] = fmt.Sprintf("%d", s.maxImageSize)
			} else if result.StatusReason == domain.ReasonSBOMTooLarge {
				domainSBOM.Annotations[domain.MaxSBOMSizeAnnotationKey] = fmt.Sprintf("%d", s.maxSBOMSize)
			}
		}
	}

	if result.SyftDocument != nil {
		domainSBOM.Content = result.SyftDocument
	}

	if result.ErrorMessage != "" && result.Status != helpersv1.Learning && result.Status != helpersv1.TooLarge {
		if result.StatusReason == domain.ReasonTooManyRequests {
			// StatusReason crossed the gRPC boundary as a plain string; wrap the
			// domain.ErrTooManyRequests sentinel so ScanService.checkCreateSBOM can
			// recognize this as a 429 (via errors.Is) and record the backoff.
			return domainSBOM, fmt.Errorf("%s: %w", result.ErrorMessage, domain.ErrTooManyRequests)
		}
		return domainSBOM, fmt.Errorf("%s", result.ErrorMessage)
	}

	// Clear retry count on success
	s.mu.Lock()
	delete(s.retryCount, imageID)
	s.mu.Unlock()

	return domainSBOM, nil
}

func (s *SidecarSBOMAdapter) handleCrash(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions, domainSBOM domain.SBOM, crashErr error) (domain.SBOM, error) {
	s.mu.Lock()
	s.evictStaleRetriesLocked()
	entry := s.retryCount[imageID]
	if entry == nil {
		entry = &crashRetry{}
		s.retryCount[imageID] = entry
	}
	entry.count++
	entry.lastSeen = time.Now()
	retries := entry.count
	s.mu.Unlock()

	logger.L().Warning("SBOM scanner sidecar crashed during scan",
		helpers.String("imageID", imageID),
		helpers.Int("retry", retries),
		helpers.Int("maxRetries", maxCrashRetries))

	if retries >= maxCrashRetries {
		// Exhausted retries — mark as TooLarge with memory-limit annotation
		s.mu.Lock()
		delete(s.retryCount, imageID)
		s.mu.Unlock()

		domainSBOM.Status = helpersv1.TooLarge
		domainSBOM.Annotations[domain.StatusReasonAnnotationKey] = domain.ReasonScannerOOM
		domainSBOM.Annotations[domain.ScannerMemoryLimitAnnotationKey] = s.memoryLimit
		if s.memoryLimit != "" {
			domainSBOM.Annotations[helpersv1.StatusMetadataKey] = fmt.Sprintf(
				"scanner OOM after %d retries (memory limit: %s)", maxCrashRetries, s.memoryLimit)
		}
		logger.L().Warning("SBOM scanner exhausted retries, marking as TooLarge",
			helpers.String("imageID", imageID))
		return domainSBOM, nil
	}

	// Return the crash error so the caller can retry later
	return domainSBOM, crashErr
}

// evictStaleRetriesLocked removes retry-count entries untouched for longer than
// retryCountTTL, bounding the map's growth for images that crash once and are never
// scanned again. Called with s.mu held; piggybacks on handleCrash rather than a background
// goroutine since crashes are rare and this keeps the map bounded without extra machinery.
func (s *SidecarSBOMAdapter) evictStaleRetriesLocked() {
	cutoff := time.Now().Add(-retryCountTTL)
	for imageID, entry := range s.retryCount {
		if entry.lastSeen.Before(cutoff) {
			delete(s.retryCount, imageID)
		}
	}
}

// Version returns the sidecar's Syft version, used as the SBOM/CVE storage cache key
// (see repositories/apiserver.go's semver comparison against the stored manifest). It only
// caches a successful Health() result: a failed/timed-out health check is never written to
// versionStr, so a transient blip (e.g. on cold start) does not permanently pin every scan
// on this pod to "unknown" and starve the storage cache (see #473) — the next call simply
// retries instead of returning a value baked in by sync.Once for the rest of the process's
// life.
//
// Concurrent callers that miss the cache are coalesced through versionGroup into a single
// in-flight Health() call: without this, two overlapping callers could each run their own
// Health() independently, and if one happened to fail while the other succeeded, the failing
// caller would return "unknown" even though the version was, at that same moment, already
// known — an avoidable cache miss for whatever that caller was about to look up. Coalescing
// means every overlapping caller observes the same outcome as the single underlying call.
func (s *SidecarSBOMAdapter) Version() string {
	s.versionMu.Lock()
	if s.versionStr != "" {
		defer s.versionMu.Unlock()
		return s.versionStr
	}
	s.versionMu.Unlock()

	v, err, _ := s.versionGroup.Do("version", func() (any, error) {
		// Another goroutine may have populated versionStr after the
		// singleflight key was released but before this closure executes.
		// Recheck the cache to avoid issuing a redundant Health() request.
		s.versionMu.Lock()
		if s.versionStr != "" {
			s.versionMu.Unlock()
			return s.versionStr, nil
		}
		s.versionMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		version, _, err := s.client.Health(ctx)
		if err != nil {
			return "", err
		}

		s.versionMu.Lock()
		defer s.versionMu.Unlock()
		s.versionStr = version

		return version, nil
	})

	if err != nil {
		logger.L().Warning("failed to get scanner version", helpers.Error(err))
		return "unknown"
	}

	return v.(string)
}

func (s *SidecarSBOMAdapter) GetMaxImageSize() int64 {
	return s.maxImageSize
}

func (s *SidecarSBOMAdapter) GetMaxSBOMSize() int {
	return s.maxSBOMSize
}

func (s *SidecarSBOMAdapter) GetMemoryLimit() string {
	return s.memoryLimit
}
