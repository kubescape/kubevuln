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
)

const maxCrashRetries = 3

// SidecarSBOMAdapter implements ports.SBOMCreator by delegating SBOM generation
// to the sbom-scanner sidecar container via gRPC over a Unix domain socket.
type SidecarSBOMAdapter struct {
	client            sbomscanner.SBOMScannerClient
	maxImageSize      int64
	maxSBOMSize       int
	scanTimeout       time.Duration
	scanEmbeddedSBOMs bool
	memoryLimit       string

	mu         sync.Mutex
	retryCount map[string]int

	versionOnce sync.Once
	versionStr  string
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
) *SidecarSBOMAdapter {
	return &SidecarSBOMAdapter{
		client:            client,
		maxImageSize:      maxImageSize,
		maxSBOMSize:       maxSBOMSize,
		scanTimeout:       scanTimeout,
		scanEmbeddedSBOMs: scanEmbeddedSBOMs,
		memoryLimit:       memoryLimit,
		retryCount:        make(map[string]int),
	}
}

func (s *SidecarSBOMAdapter) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	// Normalize image ID for consistent naming
	if imageTag != "" {
		imageID = NormalizeImageID(imageID, imageTag)
	}

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

	req := sbomscanner.ScanRequest{
		ImageID:             imageID,
		ImageTag:            imageTag,
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

	if result.SyftDocument != nil {
		domainSBOM.Content = result.SyftDocument
	}

	if result.ErrorMessage != "" && result.Status != helpersv1.Learning {
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
	s.retryCount[imageID]++
	retries := s.retryCount[imageID]
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

func (s *SidecarSBOMAdapter) Version() string {
	s.versionOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		version, _, err := s.client.Health(ctx)
		if err != nil {
			logger.L().Warning("failed to get scanner version", helpers.Error(err))
			s.versionStr = "unknown"
			return
		}
		s.versionStr = version
	})
	return s.versionStr
}
