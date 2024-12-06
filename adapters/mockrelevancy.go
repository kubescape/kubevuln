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

func (m MockRelevancyAdapter) GetRelevantFiles(_ context.Context, _, _, _ string) (mapset.Set[string], map[string]string, error) {
	return mapset.NewSet[string](), map[string]string{}, nil
}
