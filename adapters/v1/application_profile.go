package v1

import (
	"context"
	"fmt"
	"slices"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/containerinstance"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
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

func (a *ApplicationProfileAdapter) GetContainerRelevancyScans(ctx context.Context, namespace, name string) ([]ports.ContainerRelevancyScan, error) {
	var scans []ports.ContainerRelevancyScan
	applicationProfile, err := a.repository.GetApplicationProfile(ctx, namespace, name)
	if err != nil {
		return scans, fmt.Errorf("GetApplicationProfile: %w", err)
	}
	// only ready or completed application profiles are considered
	if status, ok := applicationProfile.Annotations[helpersv1.StatusMetadataKey]; !ok || !slices.Contains([]string{helpersv1.Completed, helpersv1.Ready}, status) {
		return scans, fmt.Errorf("application profile %s/%s is not ready or completed", namespace, name)
	}
	instanceIDString, ok := applicationProfile.Annotations[helpersv1.InstanceIDMetadataKey]
	if !ok {
		return nil, fmt.Errorf("instance ID not found in application profile %s/%s", namespace, name)
	}
	wlid, ok := applicationProfile.Annotations[helpersv1.WlidMetadataKey]
	if !ok {
		return nil, fmt.Errorf("WLID not found in application profile %s/%s", namespace, name)
	}
	// add a scan per container
	addContainers := func(containerType string, containers []v1beta1.ApplicationProfileContainer) {
		for _, c := range containers {
			instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(instanceIDString)
			if err != nil {
				logger.L().Error("failed to generate instance ID", helpers.Error(err))
				continue
			}
			// add container name and type to instance ID
			instanceID.(*containerinstance.InstanceID).ContainerName = c.Name
			instanceID.(*containerinstance.InstanceID).InstanceType = containerType
			scan := ports.ContainerRelevancyScan{
				ContainerName:    c.Name,
				ImageID:          c.ImageID,
				ImageTag:         c.ImageTag,
				InstanceID:       instanceID,
				InstanceIDString: instanceIDString,
				Labels:           applicationProfile.Labels,
				RelevantFiles:    mapset.NewSet[string](),
				Wlid:             wlid,
			}
			// fill relevant files
			for _, f := range c.Execs {
				scan.RelevantFiles.Add(f.Path)
			}
			for _, f := range c.Opens {
				scan.RelevantFiles.Add(f.Path)
			}
			// add container name to labels
			scan.Labels[helpersv1.ContainerNameMetadataKey] = c.Name
			scans = append(scans, scan)
		}
	}
	addContainers("container", applicationProfile.Spec.Containers)
	addContainers("initContainer", applicationProfile.Spec.InitContainers)
	addContainers("ephemeralContainer", applicationProfile.Spec.EphemeralContainers)
	return scans, nil
}
