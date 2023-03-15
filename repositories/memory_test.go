package repositories

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"gotest.tools/v3/assert"
)

func TestMemoryStore_GetCVE(t *testing.T) {
	m := NewMemoryStorage()
	ctx := context.TODO()
	got, _ := m.GetCVE(ctx, "imageID", "", "", "")
	assert.Assert(t, got.Content == nil)
	cve := domain.CVEManifest{
		ImageID:            "imageID",
		SBOMCreatorVersion: "",
		CVEScannerVersion:  "",
		CVEDBVersion:       "",
		Content:            &v1beta1.GrypeDocument{},
	}
	m.StoreCVE(ctx, cve, false)
	got, _ = m.GetCVE(ctx, "imageID", "", "", "")
	assert.Assert(t, got.Content != nil)
}

func TestMemoryStore_GetSBOM(t *testing.T) {
	m := NewMemoryStorage()
	ctx := context.TODO()
	got, _ := m.GetSBOM(ctx, "imageID", "")
	assert.Assert(t, got.Content == nil)
	got, _ = m.GetSBOMp(ctx, "imageID", "")
	assert.Assert(t, got.Content == nil)
	sbom := domain.SBOM{
		ImageID:            "imageID",
		SBOMCreatorVersion: "",
		Status:             "",
		Content:            &v1beta1.Document{},
	}
	m.StoreSBOM(ctx, sbom)
	got, _ = m.GetSBOM(ctx, "imageID", "")
	assert.Assert(t, got.Content != nil)
	got, _ = m.GetSBOMp(ctx, "imageID", "")
	assert.Assert(t, got.Content != nil)
}
