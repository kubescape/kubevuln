package adapters

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"gotest.tools/v3/assert"
)

func TestMockSBOMAdapter_CreateSBOM(t *testing.T) {
	m := NewMockSBOMAdapter(false, false)
	sbom, _ := m.CreateSBOM(context.TODO(), "image", domain.RegistryOptions{})
	assert.Assert(t, sbom.Content != nil)
}

func TestMockSBOMAdapter_CreateSBOM_Error(t *testing.T) {
	m := NewMockSBOMAdapter(true, false)
	_, err := m.CreateSBOM(context.TODO(), "image", domain.RegistryOptions{})
	assert.Assert(t, err != nil)
}

func TestMockSBOMAdapter_CreateSBOM_Timeout(t *testing.T) {
	m := NewMockSBOMAdapter(false, true)
	sbom, _ := m.CreateSBOM(context.TODO(), "image", domain.RegistryOptions{})
	assert.Assert(t, sbom.Status == domain.SBOMStatusTimedOut)
}

func TestMockSBOMAdapter_Version(t *testing.T) {
	m := NewMockSBOMAdapter(false, false)
	assert.Assert(t, m.Version() == "Mock SBOM 1.0")
}
