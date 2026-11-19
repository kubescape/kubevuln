package v1

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"testing"

	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestIsWorkloadScopedPolicy pins which exception policies may shape a result stored per
// image: only those whose applicability does not depend on the scanned workload.
func TestIsWorkloadScopedPolicy(t *testing.T) {
	apps := "apps"
	target := ExceptionTarget{
		Namespace: "team-a", Kind: "Deployment", Name: "web", APIGroup: &apps,
		Image:          "docker.io/library/nginx:1.25.0",
		WorkloadLabels: map[string]string{"app": "web"}, WorkloadLabelsResolved: true,
		NamespaceLabels: map[string]string{"team": "a"}, NamespaceLabelsResolved: true,
	}
	vulns := []sev1beta1.VulnerabilityException{{
		Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-A"},
		Status:        sev1beta1.VulnerabilityStatusNotAffected,
	}}
	spec := func(match sev1beta1.ExceptionMatch) sev1beta1.SecurityExceptionSpec {
		return sev1beta1.SecurityExceptionSpec{Match: match, Vulnerabilities: vulns}
	}
	for _, tc := range []struct {
		name       string
		namespaced bool
		match      sev1beta1.ExceptionMatch
		want       bool
	}{
		{name: "namespaced, no match", namespaced: true, want: true},
		{name: "namespaced, images only", namespaced: true, match: sev1beta1.ExceptionMatch{Images: []string{"docker.io/library/nginx:*"}}, want: true},
		{name: "cluster, no match", want: false},
		{name: "cluster, images only", match: sev1beta1.ExceptionMatch{Images: []string{"docker.io/library/nginx:*"}}, want: false},
		{name: "cluster, namespace selector", match: sev1beta1.ExceptionMatch{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}}, want: true},
		{name: "cluster, object selector", match: sev1beta1.ExceptionMatch{ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}, want: true},
		{name: "cluster, resources", match: sev1beta1.ExceptionMatch{Resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", Name: "web"}}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ses []sev1beta1.SecurityException
			var cses []sev1beta1.ClusterSecurityException
			if tc.namespaced {
				ses = []sev1beta1.SecurityException{{ObjectMeta: metav1.ObjectMeta{Name: "e", Namespace: "team-a"}, Spec: spec(tc.match)}}
			} else {
				cses = []sev1beta1.ClusterSecurityException{{ObjectMeta: metav1.ObjectMeta{Name: "e"}, Spec: spec(tc.match)}}
			}
			policies, _ := ConvertToVulnerabilityExceptionPolicies(ses, cses, target)
			require.Len(t, policies, 1, "the exception must match the target")
			assert.Equal(t, tc.want, IsWorkloadScopedPolicy(policies[0]))
			assert.Equal(t, tc.want, HasWorkloadScopedPolicy(policies))
		})
	}
}

// TestIsWorkloadScopedPolicy_BackendDesignators pins how backend policies, which carry no CRD
// sourceKind, are classified from their designators.
func TestIsWorkloadScopedPolicy_BackendDesignators(t *testing.T) {
	attrs := func(m map[string]string) []identifiers.PortalDesignator {
		return []identifiers.PortalDesignator{{DesignatorType: identifiers.DesignatorAttributes, Attributes: m}}
	}
	for _, tc := range []struct {
		name        string
		designators []identifiers.PortalDesignator
		want        bool
	}{
		{name: "none", want: false},
		{name: "account and cluster", designators: attrs(map[string]string{"customerGUID": "g", "cluster": "c", "clusterShortName": "c"}), want: false},
		{name: "registry image", designators: attrs(map[string]string{"cluster": "c", "registryName": "r", "repository": "nginx", "tag": "1.25.0"}), want: false},
		{name: "namespace", designators: attrs(map[string]string{"cluster": "c", "namespace": "team-a"}), want: true},
		{name: "kind and name", designators: attrs(map[string]string{"kind": "deployment", "name": "web"}), want: true},
		{name: "container", designators: attrs(map[string]string{"containerName": "nginx"}), want: true},
		{name: "workload label", designators: attrs(map[string]string{"app": "web"}), want: true},
		{name: "unknown key", designators: attrs(map[string]string{"somethingNew": "x"}), want: true},
		{name: "wlid", designators: []identifiers.PortalDesignator{{DesignatorType: identifiers.DesignatorWlid, WLID: "wlid://cluster-c/namespace-team-a/deployment-web"}}, want: true},
		{name: "cluster-wide wildwlid", designators: []identifiers.PortalDesignator{{DesignatorType: identifiers.DesignatorWildWlid, WildWLID: "wlid://cluster-c/"}}, want: false},
		{name: "one narrowing of two", designators: append(attrs(map[string]string{"cluster": "c"}), attrs(map[string]string{"namespace": "team-a"})...), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := armotypes.VulnerabilityExceptionPolicy{Designatores: tc.designators}
			assert.Equal(t, tc.want, IsWorkloadScopedPolicy(p))
		})
	}
}

// The cloud-over-CRD precedence (#812) is evaluated per workload. A cloud exception scoped to
// one workload must not remove an image-wide ClusterSecurityException from the image-level
// result of that workload's scans only: the shared image manifest would then depend on which
// workload was scanned last.
func TestCloudPrecedenceKeepsImageLevelResultIndependentOfWorkload(t *testing.T) {
	cse := []armotypes.VulnerabilityExceptionPolicy{{
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-A"}},
		PortalBase:            armotypes.PortalBase{Attributes: map[string]interface{}{"sourceKind": "ClusterSecurityException", "ruleId": "ClusterSecurityException/all"}},
	}}
	cloudForW1 := []armotypes.VulnerabilityExceptionPolicy{{
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-A"}},
		Designatores: []identifiers.PortalDesignator{{DesignatorType: identifiers.DesignatorAttributes,
			Attributes: map[string]string{"cluster": "c", "namespace": "team-a", "kind": "deployment", "name": "web"}}},
	}}
	// the merged list GetCVEExceptions builds for each workload
	w1 := append(append([]armotypes.VulnerabilityExceptionPolicy{}, cloudForW1...), excludeCloudCoveredPolicies(cse, cloudForW1)...)
	w2 := append([]armotypes.VulnerabilityExceptionPolicy{}, excludeCloudCoveredPolicies(cse, nil)...)

	imageResult := func(policies []armotypes.VulnerabilityExceptionPolicy) []string {
		doc := &v1beta1.GrypeDocument{Matches: []v1beta1.Match{{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-A"}}}}}
		ApplyImageWideSecurityExceptions(doc, policies)
		var ignored []string
		for _, im := range doc.IgnoredMatches {
			ignored = append(ignored, im.Vulnerability.ID)
		}
		return ignored
	}
	assert.Equal(t, []string{"CVE-A"}, imageResult(w2), "the image-wide ClusterSecurityException applies at image level")
	assert.Equal(t, imageResult(w2), imageResult(w1), "the image-level result must not depend on which workload is scanned")

	// For W1 itself, cloud precedence still holds: its own result is suppressed by the cloud
	// policy, not by the ClusterSecurityException.
	doc := &v1beta1.GrypeDocument{Matches: []v1beta1.Match{{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-A"}}}}}
	ApplySecurityExceptions(doc, WorkloadPolicies(w1), nil)
	require.Len(t, doc.IgnoredMatches, 1)
	for _, r := range doc.IgnoredMatches[0].AppliedIgnoreRules {
		assert.NotEqual(t, "ClusterSecurityException", r.SourceKind, "a cloud-covered CRD exception does not shape the workload's own result")
	}
}
