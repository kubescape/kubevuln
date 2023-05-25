package adapters

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestMockSBOMAdapter_CreateSBOM(t *testing.T) {
	m := NewMockSBOMAdapter(false, false, false)
	sbom, _ := m.CreateSBOM(context.TODO(), "image", domain.RegistryOptions{})
	assert.NotNil(t, sbom.Content)
}

func TestMockSBOMAdapter_CreateSBOM_Error(t *testing.T) {
	m := NewMockSBOMAdapter(true, false, false)
	_, err := m.CreateSBOM(context.TODO(), "image", domain.RegistryOptions{})
	assert.Error(t, err)
}

func TestMockSBOMAdapter_CreateSBOM_Timeout(t *testing.T) {
	m := NewMockSBOMAdapter(false, true, false)
	sbom, _ := m.CreateSBOM(context.TODO(), "image", domain.RegistryOptions{})
	assert.Equal(t, sbom.Status, instanceidhandler.Incomplete)
}

func TestMockSBOMAdapter_Version(t *testing.T) {
	m := NewMockSBOMAdapter(false, false, false)
	assert.Equal(t, m.Version(), "Mock SBOM 1.0")
}
