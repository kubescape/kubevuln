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

// MemoryStore implements both CVERepository and SBOMRepository with in-memory storage (maps) to be used for tests
type MemoryStore struct {
	cveManifests map[cveID]domain.CVEManifest
	sboms        map[sbomID]domain.SBOM
	getError     bool
	storeError   bool
}

var _ ports.CVERepository = (*MemoryStore)(nil)

var _ ports.SBOMRepository = (*MemoryStore)(nil)

// NewMemoryStorage initializes the MemoryStore struct and its maps
func NewMemoryStorage(getError, storeError bool) *MemoryStore {
	return &MemoryStore{
		cveManifests: map[cveID]domain.CVEManifest{},
		sboms:        map[sbomID]domain.SBOM{},
		getError:     getError,
		storeError:   storeError,
	}
}

// GetCVE returns a CVE manifest from an in-memory map
func (m *MemoryStore) GetCVE(ctx context.Context, name, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (domain.CVEManifest, error) {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.GetCVE")
	defer span.End()

	if m.getError {
		return domain.CVEManifest{}, domain.ErrMockError
	}

	id := cveID{
		Name:               name,
		SBOMCreatorVersion: SBOMCreatorVersion,
		CVEScannerVersion:  CVEScannerVersion,
		CVEDBVersion:       CVEDBVersion,
	}
	if value, ok := m.cveManifests[id]; ok {
		return value, nil
	}
	return domain.CVEManifest{}, nil
}

// StoreCVE stores a CVE manifest to an in-memory map
func (m *MemoryStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, _ bool) error {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.StoreCVE")
	defer span.End()

	if m.storeError {
		return domain.ErrMockError
	}

	id := cveID{
		Name:               cve.Name,
		SBOMCreatorVersion: cve.SBOMCreatorVersion,
		CVEScannerVersion:  cve.CVEScannerVersion,
		CVEDBVersion:       cve.CVEDBVersion,
	}
	m.cveManifests[id] = cve
	return nil
}

// StoreCVE stores a CVE Summary to an in-memory map
func (m *MemoryStore) StoreCVESummary(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.StoreCVESummary")
	defer span.End()

	if m.storeError {
		return domain.ErrMockError
	}

	id := cveID{
		Name:               cve.Name,
		SBOMCreatorVersion: cve.SBOMCreatorVersion,
		CVEScannerVersion:  cve.CVEScannerVersion,
		CVEDBVersion:       cve.CVEDBVersion,
	}

	if withRelevancy {
		idSumm := cveID{
			Name:               cvep.Name,
			SBOMCreatorVersion: cvep.SBOMCreatorVersion,
			CVEScannerVersion:  cvep.CVEScannerVersion,
			CVEDBVersion:       cvep.CVEDBVersion,
		}
		m.cveManifests[idSumm] = cvep
	}

	m.cveManifests[id] = cve
	return nil
}

// GetSBOM returns a SBOM from an in-memory map
func (m *MemoryStore) GetSBOM(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error) {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.GetSBOM")
	defer span.End()

	if m.getError {
		return domain.SBOM{}, domain.ErrMockError
	}

	id := sbomID{
		Name:               name,
		SBOMCreatorVersion: SBOMCreatorVersion,
	}
	if value, ok := m.sboms[id]; ok {
		return value, nil
	}
	return domain.SBOM{}, nil
}

// GetSBOMp returns a SBOM' from an in-memory map
func (m *MemoryStore) GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (domain.SBOM, error) {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.GetSBOMp")
	defer span.End()

	if m.getError {
		return domain.SBOM{}, domain.ErrMockError
	}

	id := sbomID{
		Name:               instanceID,
		SBOMCreatorVersion: SBOMCreatorVersion,
	}
	if value, ok := m.sboms[id]; ok {
		return value, nil
	}
	return domain.SBOM{}, nil
}

// StoreSBOM stores an SBOM to an in-memory map
func (m *MemoryStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.StoreSBOM")
	defer span.End()

	if m.storeError {
		return domain.ErrMockError
	}

	id := sbomID{
		Name:               sbom.Name,
		SBOMCreatorVersion: sbom.SBOMCreatorVersion,
	}
	m.sboms[id] = sbom
	return nil
}

// StoreVEX stores a VEX to an in-memory map
func (m *MemoryStore) StoreVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.StoreVEX")
	defer span.End()

	return nil
}
