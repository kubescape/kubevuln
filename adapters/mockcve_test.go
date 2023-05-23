package adapters

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestMockCVEAdapter_DBVersion(t *testing.T) {
	m := NewMockCVEAdapter()
	assert.Equal(t, m.DBVersion(context.TODO()), "v1.0.0")
}

func TestMockCVEAdapter_Ready(t *testing.T) {
	m := NewMockCVEAdapter()
	assert.True(t, m.Ready(context.TODO()))
}

func TestMockCVEAdapter_ScanSBOM(t *testing.T) {
	m := NewMockCVEAdapter()
	_, err := m.ScanSBOM(context.TODO(), domain.SBOM{})
	assert.NoError(t, err)
}

func TestMockCVEAdapter_Version(t *testing.T) {
	m := NewMockCVEAdapter()
	assert.Equal(t, m.Version(context.TODO()), "Mock CVE 1.0")
}
