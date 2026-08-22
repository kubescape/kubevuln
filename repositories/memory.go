package repositories

import (
	"cmp"
	"context"
	"slices"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
)

type apID struct {
	Namespace string
	Name      string
}

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
	aps          map[apID]v1beta1.ContainerProfile
	cveManifests map[cveID]domain.CVEManifest
	cveSummaries map[cveID]domain.CVEManifest
	sboms        map[sbomID]domain.SBOM
	summaryStubs []string // statuses passed to StoreCVESummaryStub, recorded for tests
	sbomStores   int      // number of StoreSBOM calls, recorded for tests
	getError     bool
	storeError   bool
}

var _ ports.ContainerProfileRepository = (*MemoryStore)(nil)

var _ ports.CVERepository = (*MemoryStore)(nil)

var _ ports.SBOMRepository = (*MemoryStore)(nil)

// SBOMStores reports how many times StoreSBOM was called, so a test can tell an SBOM that
// was written from one that was only read back.
func (m *MemoryStore) SBOMStores() int {
	return m.sbomStores
}

// NewMemoryStorage initializes the MemoryStore struct and its maps
func NewMemoryStorage(getError, storeError bool) *MemoryStore {
	return &MemoryStore{
		aps:          map[apID]v1beta1.ContainerProfile{},
		cveManifests: map[cveID]domain.CVEManifest{},
		cveSummaries: map[cveID]domain.CVEManifest{},
		sboms:        map[sbomID]domain.SBOM{},
		getError:     getError,
		storeError:   storeError,
	}
}

func (m *MemoryStore) GetContainerProfile(ctx context.Context, namespace string, name string) (v1beta1.ContainerProfile, error) {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.GetContainerProfile")
	defer span.End()

	if m.getError {
		return v1beta1.ContainerProfile{}, domain.ErrMockError
	}

	id := apID{
		Namespace: namespace,
		Name:      name,
	}
	if value, ok := m.aps[id]; ok {
		return value, nil
	}
	return v1beta1.ContainerProfile{}, nil
}

func (m *MemoryStore) StoreContainerProfile(ctx context.Context, ap v1beta1.ContainerProfile) error {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.StoreContainerProfile")
	defer span.End()

	if m.storeError {
		return domain.ErrMockError
	}

	id := apID{
		Namespace: ap.Namespace,
		Name:      ap.Name,
	}
	m.aps[id] = ap
	return nil
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

// GetCVESummary always reports no summary. It is a stub rather than a read of what
// StoreCVESummary recorded, because building a real VulnerabilityManifestSummary here would
// mean duplicating parseSeverities and parseVulnerabilitiesComponents in the test double.
//
// Nothing depends on it: the CVERepository port declares GetCVESummary, but no production
// caller has existed since the cache-hit "store the summary only if it does not exist"
// check was replaced with an unconditional re-store. Tests wanting to know what a scan flow
// handed to the summary write should use CVESummaries.
func (m *MemoryStore) GetCVESummary(ctx context.Context) (*v1beta1.VulnerabilityManifestSummary, error) {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.GetCVESummary")
	defer span.End()
	return nil, nil
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

// StoreCVESummary records the manifests a summary write was given, in a map of its own.
//
// It used to write them into m.cveManifests, the map StoreCVE writes and GetCVE reads, which
// made a summary write answer a manifest read: a flow that stored a summary without storing
// the manifest looked cached on the next scan here, and did not against APIServerStore,
// where the two are separate resources (VulnerabilityManifest, VulnerabilityManifestSummary).
// Sharing the map also meant the two calls overwrote each other's entry under the same
// cveID, so neither could be inspected afterwards.
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
		m.cveSummaries[idSumm] = cvep
	}

	m.cveSummaries[id] = cve
	return nil
}

// StoreCVESummaryStub records the status of a stub CVE summary in memory
func (m *MemoryStore) StoreCVESummaryStub(ctx context.Context, status string) error {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.StoreCVESummaryStub")
	defer span.End()

	if m.storeError {
		return domain.ErrMockError
	}

	m.summaryStubs = append(m.summaryStubs, status)
	return nil
}

// CVESummaryStubs returns the statuses passed to StoreCVESummaryStub, for tests
func (m *MemoryStore) CVESummaryStubs() []string {
	return m.summaryStubs
}

// CVESummaries returns every manifest handed to StoreCVESummary, so a test can check which
// one a scan flow summarised without wrapping the repository to intercept the call. Sorted
// so the result does not depend on Go's randomised map iteration order.
func (m *MemoryStore) CVESummaries() []domain.CVEManifest {
	out := make([]domain.CVEManifest, 0, len(m.cveSummaries))
	for _, cve := range m.cveSummaries {
		out = append(out, cve)
	}
	slices.SortFunc(out, func(a, b domain.CVEManifest) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.SBOMCreatorVersion, b.SBOMCreatorVersion),
			cmp.Compare(a.CVEScannerVersion, b.CVEScannerVersion),
			cmp.Compare(a.CVEDBVersion, b.CVEDBVersion),
		)
	})
	return out
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
		if value.Content == nil {
			// APIServerStore always reads back a document (Content: &manifest.Spec.Syft),
			// including for a status-only marker stored with no content, and callers treat a
			// nil Content as "not in storage". Without this, a stored TooLarge marker would
			// look absent here but present in production.
			value.Content = &v1beta1.SyftDocument{}
		}
		return value, nil
	}
	return domain.SBOM{}, nil
}

// StoreSBOM stores an SBOM to an in-memory map
func (m *MemoryStore) StoreSBOM(ctx context.Context, sbom domain.SBOM, _ bool) error {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.StoreSBOM")
	defer span.End()

	m.sbomStores++

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

func (m *MemoryStore) DeleteSBOM(ctx context.Context, name string) error {
	_, span := otel.Tracer("").Start(ctx, "MemoryStore.DeleteSBOM")
	defer span.End()

	if m.storeError {
		return domain.ErrMockError
	}

	for id := range m.sboms {
		if id.Name == name {
			delete(m.sboms, id)
		}
	}
	return nil
}

// StoreVEX stores a VEX to an in-memory map
func (m *MemoryStore) StoreVEX(_ context.Context, _ domain.CVEManifest, _ domain.CVEManifest, _ bool) error {
	return nil
}
