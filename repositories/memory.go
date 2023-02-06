package repositories

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
)

type cveID struct {
	Name               string
	SBOMCreatorVersion string
	CVEScannerVersion  string
	CVEDBVersion       string
}

type sbomID struct {
	Name               string
	SBOMCreatorVersion string
}

type MemoryStore struct {
	cves  map[cveID]domain.CVE
	sboms map[sbomID]domain.SBOM
}

var _ ports.CVERepository = (*MemoryStore)(nil)

var _ ports.SBOMRepository = (*MemoryStore)(nil)

func NewMemoryStorage() *MemoryStore {
	return &MemoryStore{
		cves:  map[cveID]domain.CVE{},
		sboms: map[sbomID]domain.SBOM{},
	}
}

func (m *MemoryStore) GetCVE(_ context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVE, err error) {
	id := cveID{
		Name:               imageID,
		SBOMCreatorVersion: SBOMCreatorVersion,
		CVEScannerVersion:  CVEScannerVersion,
		CVEDBVersion:       CVEDBVersion,
	}
	if value, ok := m.cves[id]; ok {
		return value, nil
	}
	return domain.CVE{}, nil
}

func (m *MemoryStore) StoreCVE(ctx context.Context, cve domain.CVE) error {
	ctx, span := otel.Tracer("").Start(ctx, "StoreCVE")
	defer span.End()
	id := cveID{
		Name:               cve.ImageID,
		SBOMCreatorVersion: cve.SBOMCreatorVersion,
		CVEScannerVersion:  cve.CVEScannerVersion,
		CVEDBVersion:       cve.CVEDBVersion,
	}
	m.cves[id] = cve
	return nil
}

func (m *MemoryStore) GetSBOM(ctx context.Context, imageID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	ctx, span := otel.Tracer("").Start(ctx, "GetSBOM")
	defer span.End()
	id := sbomID{
		Name:               imageID,
		SBOMCreatorVersion: SBOMCreatorVersion,
	}
	if value, ok := m.sboms[id]; ok {
		return value, nil
	}
	return domain.SBOM{}, nil
}

func (m *MemoryStore) GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	ctx, span := otel.Tracer("").Start(ctx, "GetSBOMp")
	defer span.End()
	id := sbomID{
		Name:               instanceID,
		SBOMCreatorVersion: SBOMCreatorVersion,
	}
	if value, ok := m.sboms[id]; ok {
		return value, nil
	}
	return domain.SBOM{}, nil
}

func (m *MemoryStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	ctx, span := otel.Tracer("").Start(ctx, "StoreSBOM")
	defer span.End()
	id := sbomID{
		Name:               sbom.ImageID,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
	}
	m.sboms[id] = sbom
	return nil
}
