package adapters

import (
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

type MockPlatform struct {
}

var _ ports.Platform = (*MockPlatform)(nil)

func NewMockPlatform() *MockPlatform {
	return &MockPlatform{}
}

func (m MockPlatform) SubmitCVE(cve domain.CVE) error {
	// TODO implement me
	panic("implement me")
}
