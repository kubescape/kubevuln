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

// TestGetContainerRelevancyScans_HostProfileSkippedCleanly covers
// kubescape/node-agent's "host" pseudo-workload: a real ContainerProfile
// (Completed/Learning status, completion=Full, a real WLID/InstanceID) that
// nonetheless has no image identity, since it isn't backed by a container
// image at all. Before this fix, ScanCP's slug computation
// (names.ImageInfoToSlug("", "")) failed for exactly this profile, logging a
// "service error - ScanCP" for every node running host monitoring. This must
// resolve as "nothing to scan" (empty scans, no error), not a scan failure --
// ScanCP only reports an error when at least one scan entry failed, so an
// empty result here is silently and correctly a no-op there.
func TestGetContainerRelevancyScans_HostProfileSkippedCleanly(t *testing.T) {
	profile := v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-host-pool-abc123-host-75fa-00ca",
			Namespace: "kubescape",
			Annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Full,
				helpersv1.StatusMetadataKey:     helpersv1.Learning,
				helpersv1.InstanceIDMetadataKey: "apiVersion-v1/namespace-host/kind-Node/name-pool-abc123/hostName-host",
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
	require.NoError(t, err, "a profile with no image identity must be skipped cleanly, not reported as a scan failure")
	assert.Empty(t, scans)
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
