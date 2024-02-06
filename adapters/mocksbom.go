package adapters

import (
	"context"
	"fmt"
	"net/http"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// MockSBOMAdapter implements a mocked SBOMCreator to be used for tests
type MockSBOMAdapter struct {
	error           bool
	timeout         bool
	toomanyrequests bool
}

var _ ports.SBOMCreator = (*MockSBOMAdapter)(nil)

// NewMockSBOMAdapter initializes the MockSBOMAdapter struct
func NewMockSBOMAdapter(error, timeout, toomanyrequests bool) *MockSBOMAdapter {
	logger.L().Info("NewMockSBOMAdapter")
	return &MockSBOMAdapter{
		error:           error,
		timeout:         timeout,
		toomanyrequests: toomanyrequests,
	}
}

// CreateSBOM returns a dummy SBOM for the given imageID
func (m MockSBOMAdapter) CreateSBOM(_ context.Context, name, imageID, imageTag string, _ domain.RegistryOptions) (domain.SBOM, error) {
	logger.L().Info("CreateSBOM")
	if m.error {
		return domain.SBOM{}, domain.ErrMockError
	}
	if m.toomanyrequests {
		return domain.SBOM{}, fmt.Errorf("failed to get image descriptor from registry: %w",
			&transport.Error{
				StatusCode: http.StatusTooManyRequests,
			},
		)
	}
	sbom := domain.SBOM{
		Name:               name,
		SBOMCreatorVersion: m.Version(),
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:  imageID,
			helpersv1.ImageTagMetadataKey: imageTag,
		},
		Labels:  tools.LabelsFromImageID(imageID),
		Content: &v1beta1.SyftDocument{},
	}
	if m.timeout {
		sbom.Status = helpersv1.Incomplete
	}
	return sbom, nil
}

// Version returns a static version
func (m MockSBOMAdapter) Version() string {
	logger.L().Info("MockSBOMAdapter.Version")
	return "Mock SBOM 1.0"
}
