package adapters

import (
	"context"
	"errors"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// MockSBOMAdapter implements a mocked SBOMCreator to be used for tests
type MockSBOMAdapter struct {
	error   bool
	timeout bool
}

var _ ports.SBOMCreator = (*MockSBOMAdapter)(nil)

// NewMockSBOMAdapter initializes the MockSBOMAdapter struct
func NewMockSBOMAdapter(error, timeout bool) *MockSBOMAdapter {
	logger.L().Info("NewMockSBOMAdapter")
	return &MockSBOMAdapter{
		error:   error,
		timeout: timeout,
	}
}

// CreateSBOM returns a dummy SBOM for the given imageID
func (m MockSBOMAdapter) CreateSBOM(ctx context.Context, imageID string, _ domain.RegistryOptions) (domain.SBOM, error) {
	logger.L().Info("CreateSBOM")
	if m.error {
		return domain.SBOM{}, errors.New("mock error")
	}
	sbom := domain.SBOM{
		ID:                 imageID,
		SBOMCreatorVersion: m.Version(),
		Annotations: map[string]string{
			instanceidhandler.ImageTagMetadataKey: imageID,
		},
		Labels: tools.LabelsFromImageID(imageID),
		Content: &v1beta1.Document{
			CreationInfo: &v1beta1.CreationInfo{
				Created: time.Now().Format(time.RFC3339),
			},
		},
	}
	if m.timeout {
		sbom.Status = domain.SBOMStatusTimedOut
	}
	return sbom, nil
}

// Version returns a static version
func (m MockSBOMAdapter) Version() string {
	logger.L().Info("MockSBOMAdapter.Version")
	return "Mock SBOM 1.0"
}
