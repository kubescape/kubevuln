package adapters

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

// MockCVEAdapter implements a mocked CVEScanner to be used for tests
type MockCVEAdapter struct {
}

var _ ports.CVEScanner = (*MockCVEAdapter)(nil)

// NewMockCVEAdapter initializes the MockCVEAdapter struct
func NewMockCVEAdapter() *MockCVEAdapter {
	return &MockCVEAdapter{}
}

// CreateRelevantCVE returns the first CVE manifest (no combination performed)
func (m MockCVEAdapter) CreateRelevantCVE(_ context.Context, cve, _ domain.CVEManifest) (domain.CVEManifest, error) {
	return cve, nil
}

// DBVersion returns a static version
func (m MockCVEAdapter) DBVersion() string {
	return "v1.0.0"
}

// Ready always returns true
func (m MockCVEAdapter) Ready() bool {
	return true
}

// ScanSBOM returns a dummy CVE manifest tagged with the given SBOM metadata
func (m MockCVEAdapter) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
	ctx, span := otel.Tracer("").Start(ctx, "ScanSBOM")
	defer span.End()
	return domain.CVEManifest{
		ImageID:            sbom.ImageID,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
		CVEScannerVersion:  m.Version(),
		CVEDBVersion:       m.DBVersion(),
		Content:            []byte("CVEManifest content"),
	}, nil
}

// UpdateDB does nothing (only otel span)
func (m MockCVEAdapter) UpdateDB(ctx context.Context) error {
	ctx, span := otel.Tracer("").Start(ctx, "UpdateDB")
	defer span.End()
	return nil
}

// Version returns a static version
func (m MockCVEAdapter) Version() string {
	return "Mock CVE 1.0"
}
