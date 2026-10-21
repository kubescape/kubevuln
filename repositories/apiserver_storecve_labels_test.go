package repositories

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The context label goes on the stored manifest, not on the caller's: that map can be
// shared with another scan of the same image, which must not see this scan's label.
func TestAPIServerStore_StoreCVELeavesTheCallersLabelsAlone(t *testing.T) {
	a := NewFakeAPIServerStorage("kubescape")
	ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{Wlid: "wlid://cluster-test/namespace-team/deployment-app", ContainerName: "app"})
	labels := map[string]string{"shared": "yes"}
	cve := domain.CVEManifest{Name: "image", Labels: labels, Content: &v1beta1.GrypeDocument{}}

	require.NoError(t, a.StoreCVE(ctx, cve, true))

	assert.Equal(t, map[string]string{"shared": "yes"}, labels, "the caller's map is unchanged")
	stored, err := a.StorageClient.VulnerabilityManifests("kubescape").Get(ctx, "image", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"shared": "yes", helpersv1.ContextMetadataKey: helpersv1.ContextMetadataKeyFiltered}, stored.Labels)

	require.NoError(t, a.StoreCVE(ctx, domain.CVEManifest{Name: "bare", Content: &v1beta1.GrypeDocument{}}, false))
	stored, err = a.StorageClient.VulnerabilityManifests("kubescape").Get(ctx, "bare", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, helpersv1.ContextMetadataKeyNonFiltered, stored.Labels[helpersv1.ContextMetadataKey], "a manifest without labels still gets the context label")
}
