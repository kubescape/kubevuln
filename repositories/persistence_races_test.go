package repositories

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestAPIServerStore_StoreCVE_ConcurrentDeletion(t *testing.T) {
	for _, phase := range []string{"get", "update", "recreate"} {
		t.Run(phase, func(t *testing.T) {
			resource := v1beta1.SchemeGroupVersion.WithResource("vulnerabilitymanifests")
			clientset := newFakeStorageClientset(&v1beta1.VulnerabilityManifest{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kubescape"},
			})
			deleted := false
			verb := phase
			if phase == "recreate" {
				verb = "get"
			}
			clientset.PrependReactor(verb, resource.Resource, func(k8stesting.Action) (bool, runtime.Object, error) {
				if deleted {
					return false, nil, nil
				}
				deleted = true
				require.NoError(t, clientset.Tracker().Delete(resource, "kubescape", name))
				if phase == "recreate" {
					// A competing creator wins after the missing-object read.
					require.NoError(t, clientset.Tracker().Create(resource, &v1beta1.VulnerabilityManifest{
						ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kubescape"},
					}, "kubescape"))
				}
				return true, nil, apierrors.NewNotFound(resource.GroupResource(), name)
			})
			repo := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
			cve := domain.CVEManifest{Name: name, CVEDBVersion: "new-db", Content: &v1beta1.GrypeDocument{
				Matches: []v1beta1.Match{{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-test"}}}},
			}}
			require.NoError(t, repo.StoreCVE(context.Background(), cve, false))
			got, err := repo.StorageClient.VulnerabilityManifests("kubescape").Get(context.Background(), name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, *cve.Content, got.Spec.Payload)
			assert.Equal(t, "new-db", got.Spec.Metadata.Tool.DatabaseVersion)
		})
	}
}

func TestAPIServerStore_StoreCVE_CanceledBeforeWrite(t *testing.T) {
	clientset := newFakeStorageClientset()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	repo := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	require.ErrorIs(t, repo.StoreCVE(ctx, domain.CVEManifest{Name: name}, false), context.Canceled)
	assert.Empty(t, clientset.Actions(), "a canceled write must not reach storage")
}

func TestAPIServerStore_StoreCVE_CanceledAfterConflict(t *testing.T) {
	clientset := newFakeStorageClientset(&v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kubescape"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := 0
	clientset.PrependReactor("update", "vulnerabilitymanifests", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		cancel()
		return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), name, nil)
	})
	repo := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	require.ErrorIs(t, repo.StoreCVE(ctx, domain.CVEManifest{Name: name}, false), context.Canceled)
	assert.Equal(t, 1, updates)
}

func TestAPIServerStore_StoreCVE_PermanentUpdateError(t *testing.T) {
	clientset := newFakeStorageClientset(&v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kubescape"},
	})
	updates := 0
	clientset.PrependReactor("update", "vulnerabilitymanifests", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), name, nil)
	})
	repo := newFakeAPIServerStore("kubescape", clientset.SpdxV1beta1())
	err := repo.StoreCVE(context.Background(), domain.CVEManifest{Name: name}, false)
	assert.True(t, apierrors.IsForbidden(err))
	assert.Equal(t, 1, updates, "permanent errors must not be retried")
}
