package v1

import (
	"context"
	"fmt"
	"slices"

	mapset "github.com/deckarep/golang-set/v2"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
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

func (a *ApplicationProfileAdapter) GetRelevantFiles(ctx context.Context, namespace, name, container string) (mapset.Set[string], map[string]string, error) {
	applicationProfile, err := a.repository.GetApplicationProfile(ctx, namespace, name)
	if err != nil {
		return nil, nil, fmt.Errorf("GetApplicationProfile: %w", err)
	}
	files := mapset.NewSet[string]()
	for _, c := range slices.Concat(applicationProfile.Spec.Containers, applicationProfile.Spec.InitContainers, applicationProfile.Spec.EphemeralContainers) {
		if c.Name == container {
			for _, f := range c.Execs {
				files.Add(f.Path)
			}
			for _, f := range c.Opens {
				files.Add(f.Path)
			}
			break
		}
	}
	labels := applicationProfile.Labels
	labels[helpersv1.ContainerNameMetadataKey] = container
	return files, labels, nil
}
