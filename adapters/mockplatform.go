package adapters

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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

// SendStatus logs the given status and details
func (m MockPlatform) SendStatus(workload domain.ScanCommand, step int) error {
	logger.L().Info(
		"SendStatus",
		helpers.String("Wlid", workload.Wlid),
		helpers.Int("step", step),
	)
	return nil
}

// SubmitCVE logs the given ImageID for CVE calculation
func (m MockPlatform) SubmitCVE(cve domain.CVEManifest) error {
	logger.L().Info(
		"SubmitCVE",
		helpers.String("ImageID", cve.ImageID),
	)
	return nil
}
