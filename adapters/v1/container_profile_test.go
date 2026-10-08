package v1

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func validContainerProfile(name, namespace string, labels map[string]string) v1beta1.ContainerProfile {
	return v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.InstanceIDMetadataKey: "apiVersion-apps/v1/namespace-kube-system/kind-DaemonSet/name-kube-proxy/containerName-kube-proxy",
				helpersv1.WlidMetadataKey:       "wlid/cluster-test/namespace-kube-system/kind-DaemonSet/name-kube-proxy",
			},
			Labels: labels,
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs:    []v1beta1.ExecCalls{{Path: "/usr/local/bin/kube-proxy"}},
			Opens:    []v1beta1.OpenCalls{{Path: "/etc/kubernetes/kube-proxy.conf"}},
			ImageID:  "sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			ImageTag: "k8s.gcr.io/kube-proxy:v1.24.3",
		},
	}
}

func TestGetContainerRelevancyScans_NilLabels(t *testing.T) {
	repo := repositories.NewMemoryStorage(false, false)
	require.NoError(t, repo.StoreContainerProfile(context.TODO(), validContainerProfile("daemonset-kube-proxy", "kube-system", nil)))

	scans, err := NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.TODO(), "kube-system", "daemonset-kube-proxy", true)
	require.NoError(t, err)

	require.Len(t, scans, 1)
	assert.Equal(t, "kube-proxy", scans[0].Labels[helpersv1.ContainerNameMetadataKey])
}

func TestGetContainerRelevancyScans_DoesNotMutateStoredProfile(t *testing.T) {
	repo := repositories.NewMemoryStorage(false, false)
	require.NoError(t, repo.StoreContainerProfile(context.TODO(), validContainerProfile("daemonset-kube-proxy", "kube-system", map[string]string{"foo": "bar"})))

	scans, err := NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.TODO(), "kube-system", "daemonset-kube-proxy", true)
	require.NoError(t, err)

	require.Len(t, scans, 1)
	assert.Equal(t, "kube-proxy", scans[0].Labels[helpersv1.ContainerNameMetadataKey])

	stored, err := repo.GetContainerProfile(context.TODO(), "kube-system", "daemonset-kube-proxy")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"foo": "bar"}, stored.Labels)
}

func TestGetContainerRelevancyScans_HostInventoryTarget(t *testing.T) {
	profile := v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-host-pool-abc123-host-75fa-00ca",
			Namespace: "kubescape",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.InstanceIDMetadataKey: "apiVersion-v1/namespace-host/kind-Node/name-host-pool-abc123/containerName-host",
				helpersv1.WlidMetadataKey:       "wlid://cluster-unknown/namespace-host/host-pool-abc123",
			},
		},
		Spec: v1beta1.ContainerProfileSpec{
			Execs: []v1beta1.ExecCalls{{Path: "/usr/sbin/iptables"}},
			Opens: []v1beta1.OpenCalls{{Path: "/etc/passwd"}},
			// ImageID/ImageTag deliberately absent -- the host has no image.
		},
	}
	repo := repositories.NewMemoryStorage(false, false)
	require.NoError(t, repo.StoreContainerProfile(context.TODO(), profile))

	scans, err := NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.TODO(), "kubescape", "node-host-pool-abc123-host-75fa-00ca", true)
	require.NoError(t, err)
	require.Len(t, scans, 1)
	assert.Equal(t, "pool-abc123", scans[0].HostNodeName)
}

// TestGetContainerRelevancyScans_RealProfileWithMissingImageIDStillReturnsScan
// guards the fix's precision: a genuinely malformed real-container profile
// missing only ImageID (ImageTag still present) must still reach slug
// computation and surface its existing error, not be silently absorbed by
// the host skip -- the skip is deliberately keyed on BOTH fields being empty.
func TestGetContainerRelevancyScans_RealProfileWithMissingImageIDStillReturnsScan(t *testing.T) {
	profile := validContainerProfile("daemonset-kube-proxy", "kube-system", nil)
	profile.Spec.ImageID = ""
	repo := repositories.NewMemoryStorage(false, false)
	require.NoError(t, repo.StoreContainerProfile(context.TODO(), profile))

	scans, err := NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.TODO(), "kube-system", "daemonset-kube-proxy", true)
	require.NoError(t, err, "GetContainerRelevancyScans itself doesn't fail here -- the slug computation failure happens in ScanCP's caller loop")
	require.Len(t, scans, 1, "a real container missing only ImageID must still be attempted, not skipped as if it were host")
	assert.Empty(t, scans[0].ImageID)
	assert.NotEmpty(t, scans[0].ImageTag)
}

func TestGetContainerRelevancyScans_NotFound(t *testing.T) {
	repo := repositories.NewMemoryStorage(false, false)

	_, err := NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.TODO(), "default", "non-existent-profile", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "container profile default/non-existent-profile not found")

	_, err = NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.TODO(), "default", "non-existent-profile", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "container profile default/non-existent-profile not found")
}

func TestGetContainerRelevancyScans_HostIdentityConflicts(t *testing.T) {
	for _, tc := range []struct{ name, instance, wlid, image string }{
		{"wrong node", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-host", "wlid://cluster-test/namespace-host/host-node-b", ""},
		{"wrong container", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-other", "wlid://cluster-test/namespace-host/host-node-a", ""},
		{"missing prefix", "apiVersion-v1/namespace-host/kind-Node/name-node-a/containerName-host", "wlid://cluster-test/namespace-host/host-node-a", ""},
		{"image present", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-host", "wlid://cluster-test/namespace-host/host-node-a", "image:tag"},
		{"extra path", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-host", "wlid://cluster/extra/namespace-host/host-node-a", ""},
		{"missing cluster", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-host", "wlid://cluster-/namespace-host/host-node-a", ""},
		{"missing namespace", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-host", "wlid://cluster-test/host-node-a", ""},
		{"wrong namespace", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-host", "wlid://cluster-test/namespace-other/host-node-a", ""},
		{"wrong kind", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-host", "wlid://cluster-test/namespace-host/deployment-node-a", ""},
		{"missing cluster prefix", "apiVersion-v1/namespace-host/kind-Node/name-host-node-a/containerName-host", "wlid://test/namespace-host/host-node-a", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := validContainerProfile("profile", "kubescape", nil)
			profile.Spec.ImageID = ""
			profile.Spec.ImageTag = tc.image
			profile.Annotations[helpersv1.InstanceIDMetadataKey] = tc.instance
			profile.Annotations[helpersv1.WlidMetadataKey] = tc.wlid
			repo := repositories.NewMemoryStorage(false, false)
			require.NoError(t, repo.StoreContainerProfile(context.Background(), profile))
			scans, err := NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.Background(), "kubescape", "profile", true)
			require.ErrorContains(t, err, "invalid host container profile identity")
			require.Empty(t, scans, "invalid identities must not produce scan work")
		})
	}
}

func TestGetContainerRelevancyScans_HostProducerIdentity(t *testing.T) {
	for _, node := range []string{"node-a", "ip-10-21-78-176.ec2.internal"} {
		for _, containerKey := range []string{"hostName", "containerName"} {
			t.Run(node+"/"+containerKey, func(t *testing.T) {
				profile := validContainerProfile("profile", "kubescape", nil)
				profile.Spec.ImageID, profile.Spec.ImageTag = "", ""
				profile.Annotations[helpersv1.InstanceIDMetadataKey] = "apiVersion-v1/namespace-host/kind-Node/name-host-" + node + "/" + containerKey + "-host"
				profile.Annotations[helpersv1.WlidMetadataKey] = "wlid://cluster-unknown/namespace-host/host-" + node
				repo := repositories.NewMemoryStorage(false, false)
				require.NoError(t, repo.StoreContainerProfile(context.Background(), profile))
				scans, err := NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.Background(), "kubescape", "profile", true)
				require.NoError(t, err)
				require.Len(t, scans, 1)
				require.Equal(t, node, scans[0].HostNodeName)
				require.Equal(t, profile.Annotations[helpersv1.WlidMetadataKey], scans[0].Wlid)
			})
		}
	}
}
func TestGetContainerRelevancyScans_UnknownImagelessSkipped(t *testing.T) {
	profile := validContainerProfile("profile", "kubescape", nil)
	profile.Spec.ImageID = ""
	profile.Spec.ImageTag = ""
	repo := repositories.NewMemoryStorage(false, false)
	require.NoError(t, repo.StoreContainerProfile(context.Background(), profile))
	scans, err := NewContainerProfileAdapter(repo).GetContainerRelevancyScans(context.Background(), "kubescape", "profile", true)
	require.NoError(t, err)
	require.Empty(t, scans)
}
