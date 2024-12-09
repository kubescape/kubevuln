package v1

import (
	"context"
	"fmt"
	"maps"
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
	// we have to return non-nil mapset.Set[string] and map[string]string
	files := mapset.NewSet[string]()
	labels := map[string]string{}
	applicationProfile, err := a.repository.GetApplicationProfile(ctx, namespace, name)
	if err != nil {
		return files, labels, fmt.Errorf("GetApplicationProfile: %w", err)
	}
	// only ready or completed application profiles are considered
	if status, ok := applicationProfile.Annotations[helpersv1.StatusMetadataKey]; !ok || !slices.Contains([]string{helpersv1.Completed, helpersv1.Ready}, status) {
		return files, labels, fmt.Errorf("application profile %s/%s is not ready or completed", namespace, name)
	}
	// fill labels
	maps.Insert(labels, maps.All(applicationProfile.Labels))
	// fill files
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
	labels[helpersv1.ContainerNameMetadataKey] = container
	return files, labels, nil
}
