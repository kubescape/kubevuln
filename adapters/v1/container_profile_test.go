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
