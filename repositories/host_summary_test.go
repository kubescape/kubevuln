package repositories

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

func TestHostSummaryNamespaceReadWrite(t *testing.T) {
	for _, tc := range []struct {
		name, wlid, namespace string
		missingHostNamespace  bool
	}{
		{"host", "wlid://cluster-test/namespace-host/host-node.a", "custom-storage", true},
		{"container in host namespace", "wlid://cluster-test/namespace-host/deployment-app", "host", false},
		{"container", "wlid://cluster-test/namespace-application/deployment-app", "application", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newFakeStorageClientset()
			client.PrependReactor("create", "vulnerabilitymanifestsummaries", func(action k8stesting.Action) (bool, runtime.Object, error) {
				// NamespaceLifecycle rejects writes to the host WLID's synthetic
				// namespace, even though the host itself exists.
				if tc.missingHostNamespace && action.GetNamespace() == "host" {
					return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "host")
				}
				return false, nil, nil
			})
			repo := newFakeAPIServerStore("custom-storage", client.SpdxV1beta1())
			ctx := context.WithValue(context.Background(), domain.WorkloadKey{}, domain.ScanCommand{Wlid: tc.wlid, ContainerName: "host"})
			ctx = context.WithValue(ctx, domain.TimestampKey{}, int64(1))
			for _, status := range []string{helpersv1.Initializing, helpersv1.Learning} {
				require.NoError(t, repo.StoreCVESummaryStub(ctx, status))
				stub, err := repo.GetCVESummary(ctx)
				require.NoError(t, err)
				require.NotNil(t, stub)
				require.Equal(t, tc.namespace, stub.Namespace)
				require.Equal(t, status, stub.Annotations[helpersv1.StatusMetadataKey])
			}
			full := domain.CVEManifest{Name: "full", Content: &v1beta1.GrypeDocument{}}
			relevant := domain.CVEManifest{Name: "relevant", Content: &v1beta1.GrypeDocument{}}
			for _, withRelevancy := range []bool{false, true} {
				require.NoError(t, repo.StoreCVESummary(ctx, full, relevant, withRelevancy))
				summary, err := repo.GetCVESummary(ctx)
				require.NoError(t, err)
				require.NotNil(t, summary)
				require.Equal(t, tc.namespace, summary.Namespace)
				require.Equal(t, tc.wlid, summary.Annotations[helpersv1.WlidMetadataKey])
				require.Equal(t, "custom-storage", summary.Spec.Vulnerabilities.ImageVulnerabilitiesObj.Namespace)
				require.Equal(t, full.Name, summary.Spec.Vulnerabilities.ImageVulnerabilitiesObj.Name)
				if withRelevancy {
					require.Equal(t, "custom-storage", summary.Spec.Vulnerabilities.WorkloadVulnerabilitiesObj.Namespace)
					require.Equal(t, relevant.Name, summary.Spec.Vulnerabilities.WorkloadVulnerabilitiesObj.Name)
				}
			}
			for _, action := range client.Actions() {
				require.Equal(t, tc.namespace, action.GetNamespace())
			}
		})
	}
}
