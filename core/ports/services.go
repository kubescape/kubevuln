package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
)

// ScanService is the port implemented by the business component ScanService
type ScanService interface {
	GenerateSBOM(ctx context.Context) error
	Ready(ctx context.Context) bool
	ScanCP(ctx context.Context) error
	ScanCVE(ctx context.Context) error
	ScanRegistry(ctx context.Context) error
	ValidateGenerateSBOM(ctx context.Context, workload domain.ScanCommand) (context.Context, error)
	ValidateScanCP(ctx context.Context, workload domain.ScanCommand) (context.Context, error)
	ValidateScanCVE(ctx context.Context, workload domain.ScanCommand) (context.Context, error)
	ValidateScanRegistry(ctx context.Context, workload domain.ScanCommand) (context.Context, error)
}
