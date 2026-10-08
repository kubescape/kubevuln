package v1

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestBackendAdapterHostExceptionsUseProfileNamespace(t *testing.T) {
	ctx := context.Background()
	store := repositories.NewFakeAPIServerStorage("storage-a")
	seGVR := schema.GroupVersionResource{Group: "kubescape.io", Version: "v1beta1", Resource: "securityexceptions"}
	cseGVR := schema.GroupVersionResource{Group: "kubescape.io", Version: "v1beta1", Resource: "clustersecurityexceptions"}
	for _, ns := range []string{"storage-a", "storage-b", "host"} {
		policy := sev1beta1.SecurityException{
			TypeMeta:   metav1.TypeMeta{APIVersion: "kubescape.io/v1beta1", Kind: "SecurityException"},
			ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: ns},
			Spec: sev1beta1.SecurityExceptionSpec{Vulnerabilities: []sev1beta1.VulnerabilityException{{
				Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-" + ns}, Status: sev1beta1.VulnerabilityStatusNotAffected,
			}}},
		}
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&policy)
		require.NoError(t, err)
		_, err = store.DynamicClient.Resource(seGVR).Namespace(ns).Create(ctx, &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{})
		require.NoError(t, err)
		_, err = store.DynamicClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}).Create(ctx, &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]interface{}{"name": ns, "labels": map[string]interface{}{"scope": ns}},
		}}, metav1.CreateOptions{})
		require.NoError(t, err)
	}
	clusterPolicy := sev1beta1.ClusterSecurityException{
		TypeMeta:   metav1.TypeMeta{APIVersion: "kubescape.io/v1beta1", Kind: "ClusterSecurityException"},
		ObjectMeta: metav1.ObjectMeta{Name: "selected-namespace"},
		Spec: sev1beta1.SecurityExceptionSpec{
			Match:           sev1beta1.ExceptionMatch{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"scope": "storage-a"}}},
			Vulnerabilities: []sev1beta1.VulnerabilityException{{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-cluster"}, Status: sev1beta1.VulnerabilityStatusNotAffected}},
		},
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&clusterPolicy)
	require.NoError(t, err)
	_, err = store.DynamicClient.Resource(cseGVR).Create(ctx, &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{})
	require.NoError(t, err)
	cloudCalls := 0
	adapter := NewBackendAdapter("account", "apiServer", "eventReceiver", "", store).WithBackendClient(&MockBackendClient{
		GetCVEExceptionsFunc: func(_ context.Context, _, _ string, designator *identifiers.PortalDesignator, _ map[string]string) ([]armotypes.VulnerabilityExceptionPolicy, error) {
			cloudCalls++
			require.Equal(t, "host", designator.Attributes["scope.namespace"], "cloud identity retains the WLID namespace")
			return nil, nil
		},
	})
	for _, tc := range []struct {
		kind, profileNamespace string
		want                   []string
	}{
		{"host", "storage-a", []string{"CVE-storage-a", "CVE-cluster"}},
		{"host", "storage-b", []string{"CVE-storage-b"}},
		{"host", "storage-a", []string{"CVE-storage-a", "CVE-cluster"}},
		{"deployment", "storage-a", []string{"CVE-host"}},
		{"host", "", []string{"CVE-host"}},
	} {
		workload := domain.ScanCommand{Wlid: "wlid://cluster-test/namespace-host/" + tc.kind + "-node.a", ContainerName: "host", Args: map[string]interface{}{domain.ArgsNamespace: tc.profileNamespace}}
		policies, _, err := adapter.GetCVEExceptions(context.WithValue(ctx, domain.WorkloadKey{}, workload))
		require.NoError(t, err)
		var got []string
		for _, policy := range policies {
			for _, vulnerability := range policy.VulnerabilityPolicies {
				got = append(got, vulnerability.Name)
			}
		}
		require.ElementsMatch(t, tc.want, got, "kind=%s profile namespace=%s", tc.kind, tc.profileNamespace)
		doc := &v1beta1.GrypeDocument{}
		for _, id := range []string{"CVE-storage-a", "CVE-storage-b", "CVE-host", "CVE-cluster"} {
			doc.Matches = append(doc.Matches, v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: id}}})
		}
		ApplySecurityExceptions(doc, policies, nil)
		var ignored []string
		for _, match := range doc.IgnoredMatches {
			ignored = append(ignored, match.Vulnerability.ID)
		}
		require.ElementsMatch(t, tc.want, ignored, "retrieved policies must suppress actual host findings")
		require.Len(t, doc.Matches, 4-len(tc.want))
	}
	require.Equal(t, 4, cloudCalls, "host policy caches must isolate profile namespaces and retain same-scope caching")
}
