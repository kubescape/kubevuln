package v1

import (
	"context"
	"fmt"
	"slices"

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

	// A ContainerProfile with no image identity has nothing to compute a CVE
	// slug from. In practice this is exactly and only the "host" pseudo-
	// workload from kubescape/node-agent's host-monitoring feature: it has a
	// real WLID/InstanceID and can reach Completed/Learning + completion=Full
	// like any other profile (there is no separate "this is host" flag on the
	// CR), but its Spec is never populated with an image, since it isn't one.
	// Returning an error here would make ScanCP report a scan failure every
	// time this profile is reconciled; skipping cleanly (empty scans, no
	// error) matches how the caller already treats "nothing to do" -- ScanCP
	// only returns an error when failed > 0, so an empty scans slice here is
	// silently and correctly a no-op there.
	if containerProfile.Spec.ImageID == "" && containerProfile.Spec.ImageTag == "" {
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
