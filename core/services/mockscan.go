package services

import (
	"context"
	"errors"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

type MockScanService struct {
	happy bool
}

var _ ports.ScanService = (*MockScanService)(nil)

func NewMockScanService(happy bool) *MockScanService {
	return &MockScanService{happy: happy}
}

func (m MockScanService) GenerateSBOM(context.Context) error {
	if m.happy {
		return nil
	}
	return errors.New("mock error")
}

func (m MockScanService) Ready(context.Context) bool {
	if m.happy {
		return true
	}
	return false
}

func (m MockScanService) ScanCVE(context.Context) error {
	if m.happy {
		return nil
	}
	return errors.New("mock error")
}

func (m MockScanService) ValidateGenerateSBOM(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	if m.happy {
		return ctx, nil
	}
	return ctx, errors.New("mock error")
}

func (m MockScanService) ValidateScanCVE(ctx context.Context, _ domain.ScanCommand) (context.Context, error) {
	if m.happy {
		return ctx, nil
	}
	return ctx, errors.New("mock error")
}
