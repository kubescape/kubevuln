package services

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/kubevuln/repositories"
	"gotest.tools/v3/assert"
)

func TestScanService_GenerateSBOM(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		sbom            domain.SBOM
		storage         bool
		getError        bool
		storeError      bool
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
			wantErr:  false, // we no longer check for timeout
		},
		{
			name:     "phase 2, get SBOM failed",
			storage:  true,
			getError: true,
			workload: true,
			wantErr:  false,
		},
		{
			name:       "phase 2, store SBOM failed",
			storage:    true,
			storeError: true,
			workload:   true,
			wantErr:    true,
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
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout)
			storage := repositories.NewMemoryStorage(tt.getError, tt.storeError)
			s := NewScanService(sbomAdapter,
				storage,
				adapters.NewMockCVEAdapter(),
				storage,
				adapters.NewMockPlatform(),
				tt.storage)
			ctx := context.TODO()
			if tt.workload {
				workload := domain.ScanCommand{
					ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
				}
				workload.Credentialslist = []types.AuthConfig{
					{
						Username: "test",
						Password: "test",
					},
					{
						RegistryToken: "test",
					},
					{
						Auth: "test",
					},
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
		createSBOMError bool
		name            string
		instanceID      string
		emptyWlid       bool
		sbom            bool
		storage         bool
		getErrorCVE     bool
		getErrorSBOM    bool
		storeErrorCVE   bool
		storeErrorSBOM  bool
		timeout         bool
		workload        bool
		wantCvep        bool
		wantErr         bool
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:     "no storage",
			workload: true,
			wantErr:  false,
		},
		{
			name:            "create SBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:      "empty wlid",
			emptyWlid: true,
			storage:   true,
			workload:  true,
			wantErr:   false,
		},
		{
			name:     "first scan",
			storage:  true,
			workload: true,
			wantErr:  false,
		},
		{
			name:         "get SBOM failed",
			getErrorSBOM: true,
			storage:      true,
			workload:     true,
			wantErr:      false,
		},
		{
			name:           "store SBOM failed",
			storeErrorSBOM: true,
			storage:        true,
			workload:       true,
			wantErr:        false,
		},
		{
			name:        "get CVE failed",
			getErrorCVE: true,
			storage:     true,
			workload:    true,
			wantErr:     false,
		},
		{
			name:          "store CVE failed",
			storeErrorCVE: true,
			storage:       true,
			workload:      true,
			wantErr:       false,
		},
		{
			name:     "timeout SBOM",
			sbom:     true,
			storage:  true,
			timeout:  true,
			workload: true,
			wantErr:  true,
		},
		{
			name:       "with SBOMp",
			sbom:       true,
			instanceID: "ee9bdd0adec9ce004572faf3492f583aa82042a8b3a9d5c7d9179dc03c531eef",
			storage:    true,
			workload:   true,
			wantCvep:   true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageHash := "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
			wlid := "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy"
			if tt.emptyWlid {
				wlid = ""
			}
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout)
			cveAdapter := adapters.NewMockCVEAdapter()
			storageSBOM := repositories.NewMemoryStorage(tt.getErrorSBOM, tt.storeErrorSBOM)
			storageCVE := repositories.NewMemoryStorage(tt.getErrorCVE, tt.storeErrorCVE)
			s := NewScanService(sbomAdapter,
				storageSBOM,
				cveAdapter,
				storageCVE,
				adapters.NewMockPlatform(),
				tt.storage)
			ctx := context.TODO()
			s.Ready(ctx)
			if tt.workload {
				workload := domain.ScanCommand{
					ImageHash: imageHash,
					Wlid:      wlid,
				}
				if tt.instanceID != "" {
					workload.InstanceID = tt.instanceID
				}
				var err error
				ctx, _ = s.ValidateScanCVE(ctx, workload)
				tools.EnsureSetup(t, err == nil)
			}
			if tt.sbom {
				sbom, err := sbomAdapter.CreateSBOM(ctx, imageHash, domain.RegistryOptions{})
				tools.EnsureSetup(t, err == nil)
				storageSBOM.StoreSBOM(ctx, sbom)
			}
			var sbomp domain.SBOM
			if tt.instanceID != "" {
				var err error
				sbomp, err = sbomAdapter.CreateSBOM(ctx, tt.instanceID, domain.RegistryOptions{})
				tools.EnsureSetup(t, err == nil)
				sbomp.Labels = map[string]string{"foo": "bar"}
				storageSBOM.StoreSBOM(ctx, sbomp)
			}
			if err := s.ScanCVE(ctx); (err != nil) != tt.wantErr {
				t.Errorf("ScanCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantCvep {
				cvep, err := storageCVE.GetCVE(ctx, sbomp.ID, sbomAdapter.Version(ctx), cveAdapter.Version(ctx), cveAdapter.DBVersion(ctx))
				tools.EnsureSetup(t, err == nil)
				assert.Assert(t, cvep.Labels != nil)
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
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(false, false),
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
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(false, false),
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

func TestScanService_ScanRegistry(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		timeout         bool
		workload        bool
		wantErr         bool
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:            "create SBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:     "timeout SBOM",
			timeout:  true,
			workload: true,
			wantErr:  true,
		},
		{
			name:     "scan",
			workload: true,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout)
			storage := repositories.NewMemoryStorage(false, false)
			s := NewScanService(sbomAdapter,
				storage,
				adapters.NewMockCVEAdapter(),
				storage,
				adapters.NewMockPlatform(),
				false)
			ctx := context.TODO()
			if tt.workload {
				workload := domain.ScanCommand{
					ImageTag: "k8s.gcr.io/kube-proxy:v1.24.3",
				}
				workload.Credentialslist = []types.AuthConfig{
					{
						Username: "test",
						Password: "test",
					},
					{
						RegistryToken: "test",
					},
					{
						Auth: "test",
					},
				}
				var err error
				ctx, _ = s.ValidateScanRegistry(ctx, workload)
				tools.EnsureSetup(t, err == nil)
			}
			if err := s.ScanRegistry(ctx); (err != nil) != tt.wantErr {
				t.Errorf("GenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanService_ValidateScanRegistry(t *testing.T) {
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
				ImageTag: "k8s.gcr.io/kube-proxy:v1.24.3",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false),
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockPlatform(),
				false)
			_, err := s.ValidateScanRegistry(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScanCVE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
