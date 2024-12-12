package adapters

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestMockPlatform_GetCVEExceptions(t *testing.T) {
	m := NewMockPlatform(true)
	_, err := m.GetCVEExceptions(context.Background())
	assert.NoError(t, err)
}

func TestMockPlatform_SubmitCVE(t *testing.T) {
	m := NewMockPlatform(true)
	ctx := context.TODO()
	err := m.SubmitCVE(ctx, domain.CVEManifest{}, domain.CVEManifest{})
	assert.NoError(t, err)
}
