package ports

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
)

type ScanService interface {
	GenerateSBOM(ctx context.Context, imageID string, workload domain.Workload) error
	Ready() bool
	ScanCVE(ctx context.Context, instanceID string, imageID string, workload domain.Workload) error
}
