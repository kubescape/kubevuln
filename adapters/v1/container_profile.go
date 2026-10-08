package v1

import (
	"context"
	"fmt"
	"slices"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	instanceidhandlerv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

type ContainerProfileAdapter struct {
	repository ports.ContainerProfileRepository
}

var _ ports.Relevancy = (*ContainerProfileAdapter)(nil)

func NewContainerProfileAdapter(repository ports.ContainerProfileRepository) *ContainerProfileAdapter {
	return &ContainerProfileAdapter{
		repository: repository,
	}
}

func (a *ContainerProfileAdapter) GetContainerRelevancyScans(ctx context.Context, namespace, name string, partialRelevancy bool) ([]ports.ContainerRelevancyScan, error) {
	var scans []ports.ContainerRelevancyScan
	containerProfile, err := a.repository.GetContainerProfile(ctx, namespace, name)
	if err != nil {
		return scans, fmt.Errorf("GetContainerProfile: %w", err)
	}
	if containerProfile.Name == "" {
		return scans, fmt.Errorf("container profile %s/%s not found", namespace, name)
	}

	// check completion status
	// if partialRelevancy is false, only full container profiles are considered
	// if partialRelevancy is true, all container profiles are considered
	completionStatus := containerProfile.Annotations[helpersv1.CompletionMetadataKey]
	if !partialRelevancy && completionStatus != helpersv1.Full {
		return scans, fmt.Errorf("container profile %s/%s: %w", namespace, name, domain.ErrPartialContainerProfile)
	}

	// only ready or completed container profiles are considered
	if status, ok := containerProfile.Annotations[helpersv1.StatusMetadataKey]; !ok || !slices.Contains([]string{helpersv1.Completed, helpersv1.Learning}, status) {
		return scans, fmt.Errorf("container profile %s/%s is not ready or completed", namespace, name)
	}
	instanceIDString, ok := containerProfile.Annotations[helpersv1.InstanceIDMetadataKey]
	if !ok {
		return nil, fmt.Errorf("instance ID not found in container profile %s/%s", namespace, name)
	}
	wlid, ok := containerProfile.Annotations[helpersv1.WlidMetadataKey]
	if !ok {
		return nil, fmt.Errorf("WLID not found in container profile %s/%s", namespace, name)
	}

	instanceID, err := instanceidhandlerv1.GenerateInstanceIDFromString(instanceIDString)
	if err != nil {
		return nil, fmt.Errorf("failed to generate instance ID: %w", err)
	}

	hostNodeName := ""
	identityLabels := instanceID.GetLabels()
	kind := identityLabels[helpersv1.RelatedKindMetadataKey]
	hostWLID := strings.HasPrefix(wlid, "wlid://") && strings.Contains(wlid, "/namespace-host/host-")
	if kind == "Node" || hostWLID {
		node := strings.TrimPrefix(instanceID.GetName(), "host-")
		expectedSuffix := "/namespace-host/host-" + node
		if kind != "Node" || identityLabels[helpersv1.RelatedNamespaceMetadataKey] != "host" ||
			!strings.HasPrefix(instanceID.GetName(), "host-") || node == "" ||
			instanceID.GetContainerName() != "host" || !hostWLID ||
			!strings.HasSuffix(wlid, expectedSuffix) || strings.Contains(node, "/") ||
			containerProfile.Spec.ImageID != "" || containerProfile.Spec.ImageTag != "" {
			return nil, fmt.Errorf("invalid host container profile identity: %s/%s", namespace, name)
		}
		hostNodeName = node
	}
	if hostNodeName == "" && containerProfile.Spec.ImageID == "" && containerProfile.Spec.ImageTag == "" {
		return scans, nil
	}

	// copy labels map so we never mutate the repository-owned profile and nil labels scan cleanly
	scanLabels := make(map[string]string, len(containerProfile.Labels)+1)
	for k, v := range containerProfile.Labels {
		scanLabels[k] = v
	}
	scanLabels[helpersv1.ContainerNameMetadataKey] = instanceID.GetContainerName()
	scan := ports.ContainerRelevancyScan{
		Completion:       completionStatus,
		HostNodeName:     hostNodeName,
		ContainerName:    instanceID.GetContainerName(),
		ImageID:          containerProfile.Spec.ImageID,
		ImageTag:         containerProfile.Spec.ImageTag,
		InstanceID:       instanceID,
		InstanceIDString: instanceIDString,
		Labels:           scanLabels,
		RelevantFiles:    mapset.NewSet[string](),
		Wlid:             wlid,
	}
	// fill relevant files
	for _, f := range containerProfile.Spec.Execs {
		scan.RelevantFiles.Add(f.Path)
	}
	for _, f := range containerProfile.Spec.Opens {
		scan.RelevantFiles.Add(f.Path)
	}
	scans = append(scans, scan)
	return scans, nil
}
