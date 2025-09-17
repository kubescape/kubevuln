package adapters

import (
	"context"

	"github.com/kubescape/kubevuln/core/ports"
)

type MockRelevancyAdapter struct {
}

var _ ports.Relevancy = (*MockRelevancyAdapter)(nil)

func NewMockRelevancyAdapter() *MockRelevancyAdapter {
	return &MockRelevancyAdapter{}
}

func (m MockRelevancyAdapter) GetContainerRelevancyScans(_ context.Context, _, _ string, _ bool) ([]ports.ContainerRelevancyScan, error) {
	return []ports.ContainerRelevancyScan{}, nil
}
