package repositories

import (
	"context"
	"testing"

	"github.com/armosec/cluster-container-scanner-api/containerscan"
	"github.com/kubescape/kubevuln/core/domain"
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
		Content:            []containerscan.CommonContainerVulnerabilityResult{},
	}
	m.StoreCVE(ctx, cve)
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
		Content:            []byte("content"),
	}
	m.StoreSBOM(ctx, sbom)
	got, _ = m.GetSBOM(ctx, "imageID", "")
	assert.Assert(t, got.Content != nil)
	got, _ = m.GetSBOMp(ctx, "imageID", "")
	assert.Assert(t, got.Content != nil)
}
