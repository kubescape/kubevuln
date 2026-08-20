package repositories

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestBrokenStore_GetCVE(t *testing.T) {
	b := NewBrokenStorage()
	_, err := b.GetCVE(context.TODO(), "", "", "", "")
	assert.Error(t, err)
}

func TestBrokenStore_GetSBOM(t *testing.T) {
	b := NewBrokenStorage()
	_, err := b.GetSBOM(context.TODO(), "", "")
	assert.Error(t, err)
}

func TestBrokenStore_StoreCVE(t *testing.T) {
	b := NewBrokenStorage()
	err := b.StoreCVE(context.TODO(), domain.CVEManifest{}, false)
	assert.Error(t, err)
}

func TestBrokenStore_StoreSBOM(t *testing.T) {
	b := NewBrokenStorage()
	err := b.StoreSBOM(context.TODO(), domain.SBOM{}, false)
	assert.Error(t, err)
}

func TestBrokenStore_GetContainerProfile(t *testing.T) {
	b := NewBrokenStorage()
	_, err := b.GetContainerProfile(context.TODO(), "", "")
	assert.Error(t, err)
}

func TestBrokenStore_GetCVESummary(t *testing.T) {
	b := NewBrokenStorage()
	summary, err := b.GetCVESummary(context.TODO())
	assert.NoError(t, err)
	assert.NotNil(t, summary)
}

func TestBrokenStore_StoreCVESummary(t *testing.T) {
	b := NewBrokenStorage()
	err := b.StoreCVESummary(context.TODO(), domain.CVEManifest{}, domain.CVEManifest{}, false)
	assert.Error(t, err)
}

func TestBrokenStore_StoreCVESummaryStub(t *testing.T) {
	b := NewBrokenStorage()
	err := b.StoreCVESummaryStub(context.TODO(), "")
	assert.Error(t, err)
}

func TestBrokenStore_StoreVEX(t *testing.T) {
	b := NewBrokenStorage()
	err := b.StoreVEX(context.TODO(), domain.CVEManifest{}, domain.CVEManifest{}, false)
	assert.Error(t, err)
}

func TestBrokenStore_DeleteSBOM(t *testing.T) {
	b := NewBrokenStorage()
	err := b.DeleteSBOM(context.TODO(), "")
	assert.Error(t, err)
}
