package repositories

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"gotest.tools/v3/assert"
)

func TestBrokenStore_GetCVE(t *testing.T) {
	b := NewBrokenStorage()
	_, err := b.GetCVE(context.TODO(), "", "", "", "")
	assert.Assert(t, err != nil)
}

func TestBrokenStore_GetSBOM(t *testing.T) {
	b := NewBrokenStorage()
	_, err := b.GetSBOM(context.TODO(), "", "")
	assert.Assert(t, err != nil)
}

func TestBrokenStore_GetSBOMp(t *testing.T) {
	b := NewBrokenStorage()
	_, err := b.GetSBOMp(context.TODO(), "", "")
	assert.Assert(t, err != nil)
}

func TestBrokenStore_StoreCVE(t *testing.T) {
	b := NewBrokenStorage()
	err := b.StoreCVE(context.TODO(), domain.CVEManifest{}, false)
	assert.Assert(t, err != nil)
}

func TestBrokenStore_StoreSBOM(t *testing.T) {
	b := NewBrokenStorage()
	err := b.StoreSBOM(context.TODO(), domain.SBOM{})
	assert.Assert(t, err != nil)
}
