package adapters

import (
	"context"
	"errors"

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
	logger.L().Info("NewMockPlatform")
	return &MockPlatform{}
}

// GetCVEExceptions returns an empty CVEExceptions
func (m MockPlatform) GetCVEExceptions(_ context.Context) (domain.CVEExceptions, error) {
	logger.L().Info("GetCVEExceptions")
	return domain.CVEExceptions{}, nil
}

// SendStatus logs the given status and details
func (m MockPlatform) SendStatus(ctx context.Context, step int) error {
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}

	logger.L().Info(
		"SendStatus",
		helpers.String("Wlid", workload.Wlid),
		helpers.Int("step", step),
	)
	return nil
}

// SubmitCVE logs the given ImageID for CVE calculation
func (m MockPlatform) SubmitCVE(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest) error {
	logger.L().Info(
		"SubmitCVE",
		helpers.String("ImageID", cve.ImageID),
	)
	return nil
}
