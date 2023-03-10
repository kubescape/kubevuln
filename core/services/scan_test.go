package services

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/repositories"
)

func TestScanService_ScanCVE_Without_SBOM(t *testing.T) {
	type fields struct {
		sbomCreator    ports.SBOMCreator
		sbomRepository ports.SBOMRepository
		cveScanner     ports.CVEScanner
		cveRepository  ports.CVERepository
		platform       ports.Platform
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "test with both repositories",
			fields: fields{
				sbomCreator:    adapters.NewMockSBOMAdapter(),
				sbomRepository: repositories.NewMemoryStorage(),
				cveScanner:     adapters.NewMockCVEAdapter(),
				cveRepository:  repositories.NewMemoryStorage(),
				platform:       adapters.NewMockPlatform(),
			},
			wantErr: true,
		},
		{
			name: "test without sbomRepository",
			fields: fields{
				sbomCreator:    adapters.NewMockSBOMAdapter(),
				sbomRepository: repositories.NewBrokenStorage(),
				cveScanner:     adapters.NewMockCVEAdapter(),
				cveRepository:  repositories.NewMemoryStorage(),
				platform:       adapters.NewMockPlatform(),
			},
			wantErr: false,
		},
		{
			name: "test without cveRepository",
			fields: fields{
				sbomCreator:    adapters.NewMockSBOMAdapter(),
				sbomRepository: repositories.NewMemoryStorage(),
				cveScanner:     adapters.NewMockCVEAdapter(),
				cveRepository:  repositories.NewBrokenStorage(),
				platform:       adapters.NewMockPlatform(),
			},
			wantErr: true,
		},
		{
			name: "test without both repositories",
			fields: fields{
				sbomCreator:    adapters.NewMockSBOMAdapter(),
				sbomRepository: repositories.NewBrokenStorage(),
				cveScanner:     adapters.NewMockCVEAdapter(),
				cveRepository:  repositories.NewBrokenStorage(),
				platform:       adapters.NewMockPlatform(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ScanService{
				sbomCreator:    tt.fields.sbomCreator,
				sbomRepository: tt.fields.sbomRepository,
				cveScanner:     tt.fields.cveScanner,
				cveRepository:  tt.fields.cveRepository,
				platform:       tt.fields.platform,
			}
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.WorkloadKey, domain.ScanCommand{})
			if err := s.ScanCVE(ctx); (err != nil) != tt.wantErr {
				t.Errorf("ScanCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
