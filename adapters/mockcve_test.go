package adapters

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"gotest.tools/v3/assert"
)

func TestMockCVEAdapter_DBVersion(t *testing.T) {
	m := NewMockCVEAdapter()
	assert.Assert(t, m.DBVersion(context.TODO()) == "v1.0.0")
}

func TestMockCVEAdapter_Ready(t *testing.T) {
	m := NewMockCVEAdapter()
	assert.Assert(t, m.Ready(context.TODO()) == true)
}

func TestMockCVEAdapter_ScanSBOM(t *testing.T) {
	m := NewMockCVEAdapter()
	_, err := m.ScanSBOM(context.TODO(), domain.SBOM{})
	assert.Assert(t, err == nil)
}

func TestMockCVEAdapter_Version(t *testing.T) {
	m := NewMockCVEAdapter()
	assert.Assert(t, m.Version(context.TODO()) == "Mock CVE 1.0")
}
