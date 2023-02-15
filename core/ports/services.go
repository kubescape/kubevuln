package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
)

// ScanService is the port implemented by the business component ScanService
type ScanService interface {
	GenerateSBOM(ctx context.Context, imageID string, workload domain.ScanCommand) error
	Ready() bool
	ScanCVE(ctx context.Context, instanceID string, imageID string, workload domain.ScanCommand) error
	ValidateGenerateSBOM(ctx context.Context, imageID string, workload domain.ScanCommand) error
	ValidateScanCVE(ctx context.Context, instanceID string, imageID string, workload domain.ScanCommand) error
}
