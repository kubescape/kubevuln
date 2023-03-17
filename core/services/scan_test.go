package services

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/repositories"
	"gotest.tools/v3/assert"
)

func TestScanService_GenerateSBOM_Phase1(t *testing.T) {
	s := NewScanService(adapters.NewMockSBOMAdapter(),
		repositories.NewMemoryStorage(),
		adapters.NewMockCVEAdapter(),
		repositories.NewMemoryStorage(),
		adapters.NewMockPlatform(),
		false)
	ctx := context.TODO()
	s.Ready(ctx)
	workload := domain.ScanCommand{
		ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
	}
	ctx, err := s.ValidateGenerateSBOM(ctx, workload)
	assert.Assert(t, err == nil)
	err = s.GenerateSBOM(ctx)
	assert.Assert(t, err == nil)
}

func TestScanService_GenerateSBOM_Phase2(t *testing.T) {
	s := NewScanService(adapters.NewMockSBOMAdapter(),
		repositories.NewMemoryStorage(),
		adapters.NewMockCVEAdapter(),
		repositories.NewMemoryStorage(),
		adapters.NewMockPlatform(),
		true)
	ctx := context.TODO()
	s.Ready(ctx)
	workload := domain.ScanCommand{
		ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
	}
	ctx, err := s.ValidateGenerateSBOM(ctx, workload)
	assert.Assert(t, err == nil)
	err = s.GenerateSBOM(ctx)
	assert.Assert(t, err == nil)
	s.ValidateScanCVE(ctx, workload)
	assert.Assert(t, err == nil)
	s.ScanCVE(ctx)
	assert.Assert(t, err == nil)
}
