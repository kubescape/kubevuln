package repositories

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestMemoryStore_GetCVE(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()
	got, _ := m.GetCVE(ctx, "imageID", "", "", "")
	assert.Nil(t, got.Content)
	cve := domain.CVEManifest{
		ID:                 "imageID",
		SBOMCreatorVersion: "",
		CVEScannerVersion:  "",
		CVEDBVersion:       "",
		Content:            &v1beta1.GrypeDocument{},
	}
	_ = m.StoreCVE(ctx, cve, false)
	got, _ = m.GetCVE(ctx, "imageID", "", "", "")
	assert.NotNil(t, got.Content)
}

func TestMemoryStore_GetSBOM(t *testing.T) {
	m := NewMemoryStorage(false, false)
	ctx := context.TODO()
	got, _ := m.GetSBOM(ctx, "imageID", "")
	assert.Nil(t, got.Content)
	got, _ = m.GetSBOMp(ctx, "imageID", "")
	assert.Nil(t, got.Content)
	sbom := domain.SBOM{
		ID:                 "imageID",
		SBOMCreatorVersion: "",
		Status:             "",
		Content:            &v1beta1.Document{},
	}
	_ = m.StoreSBOM(ctx, sbom)
	got, _ = m.GetSBOM(ctx, "imageID", "")
	assert.NotNil(t, got.Content)
	got, _ = m.GetSBOMp(ctx, "imageID", "")
	assert.NotNil(t, got.Content)
}
