package adapters

import (
	"context"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

// MockPlatform implements a mocked Platform to be used for tests
type MockPlatform struct {
	wantEmptyReport bool
}

var _ ports.Platform = (*MockPlatform)(nil)

// NewMockPlatform initializes the MockPlatform struct
func NewMockPlatform(wantEmptyReport bool) *MockPlatform {
	logger.L().Info("keepLocal config is true, statuses and scan reports won't be sent to Armo cloud")
	return &MockPlatform{
		wantEmptyReport: wantEmptyReport,
	}
}

// GetCVEExceptions returns an empty CVEExceptions
func (m MockPlatform) GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, error) {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.GetCVEExceptions")
	defer span.End()
	return domain.CVEExceptions{}, nil
}

func (m MockPlatform) ReportError(ctx context.Context, _ error) error {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.ReportError")
	defer span.End()
	return nil
}

// SendStatus logs the given status and details
func (m MockPlatform) SendStatus(ctx context.Context, _ int) error {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.SendStatus")
	defer span.End()
	return nil
}

// SubmitCVE logs the given ID for CVE calculation
func (m MockPlatform) SubmitCVE(ctx context.Context, _ domain.CVEManifest, _ domain.CVEManifest) error {
	_, span := otel.Tracer("").Start(ctx, "MockPlatform.SubmitCVE")
	defer span.End()
	return nil
}
