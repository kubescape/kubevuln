package adapters

import (
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

// MockPlatform implements a mocked Platform to be used for tests
type MockPlatform struct {
}

var _ ports.Platform = (*MockPlatform)(nil)

// NewMockPlatform initializes the MockPlatform struct
func NewMockPlatform() *MockPlatform {
	return &MockPlatform{}
}

// SubmitCVE ...
func (m MockPlatform) SubmitCVE(cve domain.CVEManifest) error {
	// TODO implement me
	panic("implement me")
}
