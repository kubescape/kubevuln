package adapters

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
)

// MockSBOMAdapter implements a mocked SBOMCreator to be used for tests
type MockSBOMAdapter struct {
}

var _ ports.SBOMCreator = (*MockSBOMAdapter)(nil)

// NewMockSBOMAdapter initializes the MockSBOMAdapter struct
func NewMockSBOMAdapter() *MockSBOMAdapter {
	logger.L().Info("NewMockSBOMAdapter")
	return &MockSBOMAdapter{}
}

// CreateSBOM returns a dummy SBOM for the given imageID
func (m MockSBOMAdapter) CreateSBOM(ctx context.Context, imageID string, _ domain.RegistryOptions) (domain.SBOM, error) {
	logger.L().Info("CreateSBOM")
	return domain.SBOM{
		ImageID:            imageID,
		SBOMCreatorVersion: m.Version(ctx),
		Content:            &softwarecomposition.Document{},
	}, nil
}

// Version returns a static version
func (m MockSBOMAdapter) Version(_ context.Context) string {
	logger.L().Info("MockSBOMAdapter.Version")
	return "Mock SBOM 1.0"
}
