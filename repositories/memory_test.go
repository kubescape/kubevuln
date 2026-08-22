package repositories

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_GetCVE(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()
	got, _ := m.GetCVE(ctx, "name", "", "", "")
	assert.Nil(t, got.Content)
	cve := domain.CVEManifest{
		Name:               "name",
		SBOMCreatorVersion: "",
		CVEScannerVersion:  "",
		CVEDBVersion:       "",
		Content:            &v1beta1.GrypeDocument{},
	}
	_ = m.StoreCVE(ctx, cve, false)
	got, _ = m.GetCVE(ctx, "name", "", "", "")
	assert.NotNil(t, got.Content)
}

func TestMemoryStore_GetSBOM(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()
	got, _ := m.GetSBOM(ctx, "name", "")
	assert.Nil(t, got.Content)
	sbom := domain.SBOM{
		Name:               "name",
		SBOMCreatorVersion: "",
		Status:             "",
		Content:            &v1beta1.SyftDocument{},
	}
	_ = m.StoreSBOM(ctx, sbom, false)
	got, _ = m.GetSBOM(ctx, "name", "")
	assert.NotNil(t, got.Content)
}

// TestMemoryStore_SummaryWriteDoesNotSatisfyManifestRead is the property that went wrong
// while summaries shared the manifest map.
//
// Against APIServerStore these are two different resources, VulnerabilityManifest and
// VulnerabilityManifestSummary, so storing a summary can never make GetCVE find a manifest.
// A test double that answers the read anyway lets a flow look cached here that would miss
// in production, which is the wrong direction for a double to be wrong in.
func TestMemoryStore_SummaryWriteDoesNotSatisfyManifestRead(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()

	cve := domain.CVEManifest{Name: "name", Content: &v1beta1.GrypeDocument{}}
	require.NoError(t, m.StoreCVESummary(ctx, cve, domain.CVEManifest{}, false))

	got, err := m.GetCVE(ctx, "name", "", "", "")
	require.NoError(t, err)
	assert.Nil(t, got.Content, "a summary write must not satisfy a manifest read")
}

// TestMemoryStore_ManifestAndSummaryDoNotOverwriteEachOther covers the other half: sharing
// one map meant the second of the two calls replaced the first one's entry under the same
// cveID, so neither could be read back afterwards.
func TestMemoryStore_ManifestAndSummaryDoNotOverwriteEachOther(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()

	manifest := domain.CVEManifest{Name: "name", Wlid: "manifest", Content: &v1beta1.GrypeDocument{}}
	summarised := domain.CVEManifest{Name: "name", Wlid: "summary", Content: &v1beta1.GrypeDocument{}}

	require.NoError(t, m.StoreCVE(ctx, manifest, false))
	require.NoError(t, m.StoreCVESummary(ctx, summarised, domain.CVEManifest{}, false))

	got, err := m.GetCVE(ctx, "name", "", "", "")
	require.NoError(t, err)
	assert.Equal(t, "manifest", got.Wlid, "the summary write must not replace the stored manifest")

	summaries := m.CVESummaries()
	require.Len(t, summaries, 1)
	assert.Equal(t, "summary", summaries[0].Wlid)
}

// TestMemoryStore_CVESummaries covers the accessor that makes the summary write inspectable
// without wrapping the repository, including the relevancy case where StoreCVESummary is
// handed two manifests and both are recorded.
func TestMemoryStore_CVESummaries(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()

	assert.Empty(t, m.CVESummaries())

	cve := domain.CVEManifest{Name: "image", Content: &v1beta1.GrypeDocument{}}
	cvep := domain.CVEManifest{Name: "container", Content: &v1beta1.GrypeDocument{}}
	require.NoError(t, m.StoreCVESummary(ctx, cve, cvep, true))

	// Sorted by name, so the result does not depend on map iteration order.
	summaries := m.CVESummaries()
	require.Len(t, summaries, 2)
	assert.Equal(t, "container", summaries[0].Name)
	assert.Equal(t, "image", summaries[1].Name)

	// withRelevancy false records only the unfiltered manifest.
	m2 := NewMemoryStorage(false, false)
	require.NoError(t, m2.StoreCVESummary(ctx, cve, cvep, false))
	require.Len(t, m2.CVESummaries(), 1)
	assert.Equal(t, "image", m2.CVESummaries()[0].Name)
}

func TestMemoryStore_StoreCVESummary_ReportsStoreError(t *testing.T) {
	m := NewMemoryStorage(false, true)
	err := m.StoreCVESummary(context.TODO(), domain.CVEManifest{Name: "name"}, domain.CVEManifest{}, false)
	assert.ErrorIs(t, err, domain.ErrMockError)
	assert.Empty(t, m.CVESummaries(), "a failed store must record nothing")
}

// TestMemoryStore_GetCVESummary_IsAStub pins the stub as deliberate rather than an oversight,
// so a future change that starts returning something has to update this too.
func TestMemoryStore_GetCVESummary_IsAStub(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()
	require.NoError(t, m.StoreCVESummary(ctx, domain.CVEManifest{Name: "name"}, domain.CVEManifest{}, false))

	summary, err := m.GetCVESummary(ctx)
	require.NoError(t, err)
	assert.Nil(t, summary)
}
