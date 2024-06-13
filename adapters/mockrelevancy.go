package adapters

import (
	"context"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/kubevuln/core/ports"
)

type MockRelevancyAdapter struct {
}

var _ ports.Relevancy = (*MockRelevancyAdapter)(nil)

func NewMockRelevancyAdapter() *MockRelevancyAdapter {
	return &MockRelevancyAdapter{}
}

func (m MockRelevancyAdapter) GetRelevantFiles(ctx context.Context, instanceID, container string) (mapset.Set[string], error) {
	return mapset.NewSet[string](), nil
}
