package adapters

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"gotest.tools/v3/assert"
)

func TestMockSBOMAdapter_CreateSBOM(t *testing.T) {
	m := NewMockSBOMAdapter()
	sbom, _ := m.CreateSBOM(context.TODO(), "imageID", domain.RegistryOptions{})
	assert.Assert(t, sbom.Content != nil)
}

func TestMockSBOMAdapter_Version(t *testing.T) {
	m := NewMockSBOMAdapter()
	assert.Assert(t, m.Version(context.TODO()) == "Mock SBOM 1.0")
}
