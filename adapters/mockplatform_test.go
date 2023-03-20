package adapters

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"gotest.tools/v3/assert"
)

func TestMockPlatform_GetCVEExceptions(t *testing.T) {
	m := NewMockPlatform()
	_, err := m.GetCVEExceptions(context.Background())
	assert.Assert(t, err == nil)
}

func TestMockPlatform_SendStatus(t *testing.T) {
	m := NewMockPlatform()
	ctx := context.TODO()
	err := m.SendStatus(ctx, domain.Done)
	assert.Assert(t, err != nil)
	ctx = context.WithValue(ctx, domain.WorkloadKey, domain.ScanCommand{})
	err = m.SendStatus(ctx, domain.Done)
	assert.Assert(t, err == nil)
}

func TestMockPlatform_SubmitCVE(t *testing.T) {
	m := NewMockPlatform()
	ctx := context.TODO()
	err := m.SubmitCVE(ctx, domain.CVEManifest{}, domain.CVEManifest{})
	assert.Assert(t, err == nil)
}
