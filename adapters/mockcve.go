package adapters

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

type MockCVEAdapter struct {
}

var _ ports.CVEScanner = (*MockCVEAdapter)(nil)

func NewMockCVEAdapter() *MockCVEAdapter {
	return &MockCVEAdapter{}
}

func (m MockCVEAdapter) CreateRelevantCVE(_ context.Context, cve, _ domain.CVE) (domain.CVE, error) {
	return cve, nil
}

func (m MockCVEAdapter) DBVersion() string {
	return "v1.0.0"
}

func (m MockCVEAdapter) Ready() bool {
	return true
}

func (m MockCVEAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVE, error) {
	ctx, span := otel.Tracer("").Start(ctx, "ScanSBOM")
	defer span.End()
	return domain.CVE{
		ImageID:            sbom.ImageID,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  m.Version(),
		CVEDBVersion:       m.DBVersion(),
		Content:            []byte("CVE content"),
	}, nil
}

func (m MockCVEAdapter) UpdateDB(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "UpdateDB")
	defer span.End()
	return nil
}

func (m MockCVEAdapter) Version() string {
	return "Mock CVE 1.0"
}
