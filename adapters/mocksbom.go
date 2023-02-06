package adapters

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

type MockSBOMAdapter struct {
}

var _ ports.SBOMCreator = (*MockSBOMAdapter)(nil)

func NewMockSBOMAdapter() *MockSBOMAdapter {
	return &MockSBOMAdapter{}
}

func (m MockSBOMAdapter) CreateSBOM(ctx context.Context, imageID string, _ domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "CreateSBOM")
	defer span.End()
	return domain.SBOM{
		ImageID:            imageID,
		SBOMCreatorVersion: m.Version(),
		Content:            []byte("SBOM content"),
	}, nil
}

func (m MockSBOMAdapter) Version() string {
	return "Mock SBOM 1.0"
}
