package v1

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/identifiers"
	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
	instanceidv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"k8s.io/apimachinery/pkg/util/validation"
)

// WithClusterName supplies the authoritative cluster for host report routing.
func (a *BackendAdapter) WithClusterName(cluster string) *BackendAdapter {
	a.clusterConfig.ClusterName = cluster
	return a
}

// validatedHostReportNode requires the same positive identity as host CP scanning,
// including its instance slug. Directory sources alone are not host authority.
func validatedHostReportNode(workload domain.ScanCommand) (string, error) {
	node := rawNameFromWlid(workload.Wlid)
	cluster := wlidpkg.GetClusterFromWlid(workload.Wlid)
	if cluster == "" || wlidpkg.IsWlidValid(workload.Wlid) != nil ||
		workload.Wlid != "wlid://cluster-"+cluster+"/namespace-host/host-"+node ||
		node == "" || len(validation.IsDNS1123Subdomain(node)) != 0 || workload.ContainerName != "host" ||
		workload.ImageHash != "" || workload.ImageTag != "" || workload.ImageTagNormalized != "" {
		return "", fmt.Errorf("invalid host report workload identity")
	}
	for _, containerKey := range []string{"hostName", "containerName"} {
		instance, err := instanceidv1.GenerateInstanceIDFromString("apiVersion-v1/namespace-host/kind-Node/name-host-" + node + "/" + containerKey + "-host")
		if err != nil {
			return "", err
		}
		slug, err := instance.GetSlug(false)
		if err == nil && slug == workload.InstanceID {
			return node, nil
		}
	}
	return "", fmt.Errorf("host report instance does not match source WLID")
}

func (a *BackendAdapter) hostReportWorkload(workload domain.ScanCommand, cve, relevant domain.CVEManifest, scanID, executionID string) (domain.ScanCommand, map[string]string, string, error) {
	if cve.Labels[helpersv1.ArtifactTypeMetadataKey] != helpersv1.HostArtifactType &&
		!strings.EqualFold(wlidpkg.GetKindFromWlid(workload.Wlid), "host") {
		return workload, nil, scanID, nil
	}
	node, err := validatedHostReportNode(workload)
	if err != nil {
		return workload, nil, scanID, err
	}
	cluster := a.clusterConfig.ClusterName
	if cluster == "" || strings.EqualFold(cluster, "unknown") || strings.TrimSpace(cluster) != cluster || strings.ContainsAny(cluster, "/\x00\r\n\t ") || a.clusterConfig.AccountID == "" {
		return workload, nil, scanID, fmt.Errorf("host reports require an authenticated account and configured real cluster")
	}
	uid, revision := cve.Annotations[domain.HostInventoryUIDAnnotationKey], cve.Annotations[domain.HostInventoryResourceVersionAnnotationKey]
	for _, manifest := range []domain.CVEManifest{cve, relevant} {
		if manifest.Content == nil && manifest.Name == "" && manifest.Labels == nil {
			continue
		}
		if manifest.Labels[helpersv1.ArtifactTypeMetadataKey] != helpersv1.HostArtifactType ||
			manifest.Content == nil || manifest.Content.Source == nil || manifest.Content.Source.Type != "directory" ||
			uid == "" || revision == "" || manifest.Annotations[domain.HostInventoryUIDAnnotationKey] != uid ||
			manifest.Annotations[domain.HostInventoryResourceVersionAnnotationKey] != revision ||
			manifest.Annotations[helpersv1.WlidMetadataKey] != workload.Wlid || manifest.SBOMCreatorName == "" || manifest.SBOMCreatorVersion == "" {
			return workload, nil, scanID, fmt.Errorf("invalid or inconsistent host inventory report provenance")
		}
	}
	if cve.Content == nil {
		return workload, nil, scanID, fmt.Errorf("host inventory report is missing content")
	}
	profileHash := relevant.Annotations[domain.HostProfilePathsHashAnnotationKey]
	if relevant.Content != nil && profileHash == "" {
		return workload, nil, scanID, fmt.Errorf("host profile report is missing relevance snapshot identity")
	}
	attrs := map[string]string{
		identifiers.AttributeKind: "Node", identifiers.AttributeApiVersion: "v1", identifiers.AttributeNamespace: "",
		identifiers.AttributeName: node, identifiers.AttributeCluster: cluster, identifiers.AttributeContainerName: "host",
		helpersv1.WlidMetadataKey: workload.Wlid, helpersv1.ScanIdMetadataKey: scanID,
		domain.HostInventoryUIDAnnotationKey: uid, domain.HostInventoryResourceVersionAnnotationKey: revision,
		domain.HostInventoryToolNameAnnotationKey: cve.SBOMCreatorName, helpersv1.ToolVersionMetadataKey: cve.SBOMCreatorVersion,
		domain.HostProfilePathsHashAnnotationKey: profileHash,
	}
	workload.Wlid = "wlid://cluster-" + cluster + "/namespace-*/node-" + node
	inventoryHash := sha256.Sum256([]byte(workload.Wlid + "\x00" + uid + "\x00" + revision))
	workload.ImageHash = fmt.Sprintf("directory-inventory:%x", inventoryHash)
	// Host uploads must never select registry or volume ingestion, even when the
	// caller's args contain unrelated routing fields.
	workload.Args = nil
	// A new upload execution may observe a newer CVE database or exception
	// policy even when inventory and profile are unchanged. The backend keys
	// immutable findings by scan ID; transport retries reuse this one ID.
	uploadHash := sha256.Sum256([]byte(scanID + "\x00" + workload.ImageHash + "\x00" + profileHash + "\x00" + executionID))
	return workload, attrs, fmt.Sprintf("host-%x", uploadHash), nil
}
