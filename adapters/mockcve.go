package adapters

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
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
func (m MockCVEAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
	logger.L().Info("ScanSBOM")
	return domain.CVEManifest{
		ID:                 sbom.ID,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  m.Version(ctx),
		CVEDBVersion:       m.DBVersion(ctx),
		Annotations:        sbom.Annotations,
		Labels:             sbom.Labels,
		Content:            &v1beta1.GrypeDocument{},
	}, nil
}

// Version returns a static version
func (m MockCVEAdapter) Version(_ context.Context) string {
	logger.L().Info("MockCVEAdapter.Version")
	return "Mock CVE 1.0"
}
