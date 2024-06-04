package v1

import (
	"context"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/kubevuln/core/ports"
)

type ApplicationProfileAdapter struct {
	repository ports.ApplicationProfileRepository
}

var _ ports.Relevancy = (*ApplicationProfileAdapter)(nil)

func NewApplicationProfileAdapter(repository ports.ApplicationProfileRepository) *ApplicationProfileAdapter {
	return &ApplicationProfileAdapter{
		repository: repository,
	}
}

func (a *ApplicationProfileAdapter) GetRelevantFiles(ctx context.Context, instanceID, container string) (mapset.Set[string], error) {
	//TODO implement me
	return mapset.NewSet[string](), nil
}
