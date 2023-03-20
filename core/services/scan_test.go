package services

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/kubevuln/repositories"
)

func TestScanService_GenerateSBOM(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		sbom            domain.SBOM
		storage         bool
		timeout         bool
		workload        bool
		wantErr         bool
	}{
		{
			name:     "phase 1, no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:     "phase 1",
			workload: true,
			wantErr:  false,
		},
		{
			name:            "phase 1, createSBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:     "phase 1, timeout",
			timeout:  true,
			workload: true,
			wantErr:  true,
		},
		{
			name:     "phase 2, create and store SBOM",
			storage:  true,
			workload: true,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout),
				repositories.NewMemoryStorage(),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(),
				adapters.NewMockPlatform(),
				tt.storage)
			ctx := context.TODO()
			if tt.workload {
				workload := domain.ScanCommand{
					ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
				}
				var err error
				ctx, _ = s.ValidateGenerateSBOM(ctx, workload)
				tools.EnsureSetup(t, err == nil)
			}
			if err := s.GenerateSBOM(ctx); (err != nil) != tt.wantErr {
				t.Errorf("GenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanService_ScanCVE(t *testing.T) {
	tests := []struct {
		name     string
		sbom     bool
		sbomp    bool
		timeout  bool
		workload bool
		wantErr  bool
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:     "missing SBOM",
			workload: true,
			wantErr:  true,
		},
		{
			name:     "timeout SBOM",
			sbom:     true,
			timeout:  true,
			workload: true,
			wantErr:  true,
		},
		{
			name:     "missing SBOMp",
			sbom:     true,
			workload: true,
			wantErr:  false,
		},
		{
			name:     "with SBOMp",
			sbom:     true,
			sbomp:    true,
			workload: true,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageHash := "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
			wlid := "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy"
			sbomAdapter := adapters.NewMockSBOMAdapter(false, tt.timeout)
			storage := repositories.NewMemoryStorage()
			s := NewScanService(sbomAdapter,
				storage,
				adapters.NewMockCVEAdapter(),
				storage,
				adapters.NewMockPlatform(),
				true)
			ctx := context.TODO()
			s.Ready(ctx)
			if tt.workload {
				workload := domain.ScanCommand{
					ImageHash: imageHash,
					Wlid:      wlid,
				}
				var err error
				ctx, _ = s.ValidateScanCVE(ctx, workload)
				tools.EnsureSetup(t, err == nil)
			}
			if tt.sbom {
				sbom, err := sbomAdapter.CreateSBOM(ctx, imageHash, domain.RegistryOptions{})
				tools.EnsureSetup(t, err == nil)
				storage.StoreSBOM(ctx, sbom)
			}
			if tt.sbomp {
				sbomp, err := sbomAdapter.CreateSBOM(ctx, wlid, domain.RegistryOptions{})
				tools.EnsureSetup(t, err == nil)
				storage.StoreSBOM(ctx, sbomp)
			}
			if err := s.ScanCVE(ctx); (err != nil) != tt.wantErr {
				t.Errorf("ScanCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanService_ValidateGenerateSBOM(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  bool
	}{
		{
			name:     "missing imageID",
			workload: domain.ScanCommand{},
			wantErr:  true,
		},
		{
			name: "with imageID",
			workload: domain.ScanCommand{
				ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false),
				repositories.NewMemoryStorage(),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(),
				adapters.NewMockPlatform(),
				false)
			_, err := s.ValidateGenerateSBOM(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestScanService_ValidateScanCVE(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  bool
	}{
		{
			name:     "missing Wlid",
			workload: domain.ScanCommand{},
			wantErr:  true,
		},
		{
			name: "missing ImageHash",
			workload: domain.ScanCommand{
				Wlid: "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			},
			wantErr: true,
		},
		{
			name: "with Wlid and ImageHash",
			workload: domain.ScanCommand{
				ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
				Wlid:      "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false),
				repositories.NewMemoryStorage(),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(),
				adapters.NewMockPlatform(),
				false)
			_, err := s.ValidateScanCVE(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScanCVE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
