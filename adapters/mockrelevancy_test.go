package adapters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMockRelevancyAdapter(t *testing.T) {
	m := NewMockRelevancyAdapter()
	assert.NotNil(t, m)
}

func TestMockRelevancyAdapter_GetContainerRelevancyScans(t *testing.T) {
	m := NewMockRelevancyAdapter()
	scans, err := m.GetContainerRelevancyScans(context.TODO(), "wlid", "container", false)
	assert.NoError(t, err)
	assert.Empty(t, scans)
}
