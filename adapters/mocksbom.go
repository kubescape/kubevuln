package adapters

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

// MockSBOMAdapter implements a mocked SBOMCreator to be used for tests
type MockSBOMAdapter struct {
}

var _ ports.SBOMCreator = (*MockSBOMAdapter)(nil)

// NewMockSBOMAdapter initializes the MockSBOMAdapter struct
func NewMockSBOMAdapter() *MockSBOMAdapter {
	return &MockSBOMAdapter{}
}

// CreateSBOM returns a dummy SBOM for the given imageID
func (m MockSBOMAdapter) CreateSBOM(ctx context.Context, imageID string, _ domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "CreateSBOM")
	defer span.End()
	return domain.SBOM{
		ImageID:            imageID,
		SBOMCreatorVersion: m.Version(),
		Content:            []byte("SBOM content"),
	}, nil
}

// Version returns a static version
func (m MockSBOMAdapter) Version() string {
	return "Mock SBOM 1.0"
}
