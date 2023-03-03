package adapters

import (
	"context"

	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

// MockCVEAdapter implements a mocked CVEScanner to be used for tests
type MockCVEAdapter struct {
}

var _ ports.CVEScanner = (*MockCVEAdapter)(nil)

// NewMockCVEAdapter initializes the MockCVEAdapter struct
func NewMockCVEAdapter() *MockCVEAdapter {
	logger.L().Info("NewMockCVEAdapter")
	return &MockCVEAdapter{}
}

// CreateRelevantCVE returns the first CVE manifest (no combination performed)
func (m MockCVEAdapter) CreateRelevantCVE(_ context.Context, cve, _ domain.CVEManifest) (domain.CVEManifest, error) {
	logger.L().Info("CreateRelevantCVE")
	return cve, nil
}

// DBVersion returns a static version
func (m MockCVEAdapter) DBVersion(context.Context) string {
	logger.L().Info("MockCVEAdapter.DBVersion")
	return "v1.0.0"
}

// Ready always returns true
func (m MockCVEAdapter) Ready(context.Context) bool {
	logger.L().Info("MockCVEAdapter.Ready")
	return true
}

// ScanSBOM returns a dummy CVE manifest tagged with the given SBOM metadata
func (m MockCVEAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM, _ domain.CVEExceptions) (domain.CVEManifest, error) {
	logger.L().Info("ScanSBOM")
	return *domain.NewCVEManifest(
		sbom.ImageID,
		sbom.SBOMCreatorVersion,
		m.Version(ctx),
		m.DBVersion(ctx),
		[]cs.CommonContainerVulnerabilityResult{},
	), nil
}

// UpdateDB does nothing (only otel span)
func (m MockCVEAdapter) UpdateDB(_ context.Context) error {
	logger.L().Info("UpdateDB")
	return nil
}

// Version returns a static version
func (m MockCVEAdapter) Version(_ context.Context) string {
	logger.L().Info("MockCVEAdapter.Version")
	return "Mock CVE 1.0"
}
