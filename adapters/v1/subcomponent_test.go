package v1

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPURLMatches(t *testing.T) {
	tests := []struct {
		name         string
		subcomponent string
		purl         string
		want         bool
	}{
		{name: "unversioned matches any version", subcomponent: "pkg:npm/lodash", purl: "pkg:npm/lodash@4.17.20", want: true},
		{name: "unversioned matches unversioned", subcomponent: "pkg:npm/lodash", purl: "pkg:npm/lodash", want: true},
		{name: "version matches same version", subcomponent: "pkg:npm/lodash@4.17.20", purl: "pkg:npm/lodash@4.17.20", want: true},
		{name: "version does not match other version", subcomponent: "pkg:npm/lodash@4.17.20", purl: "pkg:npm/lodash@4.17.21", want: false},
		{name: "version does not match unversioned package", subcomponent: "pkg:npm/lodash@4.17.20", purl: "pkg:npm/lodash", want: false},
		{name: "different name does not match", subcomponent: "pkg:npm/lodash", purl: "pkg:npm/elliptic@6.5.4", want: false},
		{name: "different type does not match", subcomponent: "pkg:npm/lodash", purl: "pkg:golang/lodash", want: false},
		{name: "type is case-insensitive", subcomponent: "pkg:NPM/lodash", purl: "pkg:npm/lodash@1.0.0", want: true},
		{name: "namespace must match", subcomponent: "pkg:golang/github.com/a/pkg", purl: "pkg:golang/github.com/b/pkg", want: false},
		{name: "encoded namespace matches", subcomponent: "pkg:npm/%40octokit/request-error", purl: "pkg:npm/%40octokit/request-error@5.0.0", want: true},
		{name: "namespaced does not match bare name", subcomponent: "pkg:npm/%40octokit/request-error", purl: "pkg:npm/request-error@5.0.0", want: false},
		{name: "deb package with qualifiers", subcomponent: "pkg:deb/debian/openssl", purl: "pkg:deb/debian/openssl@1.1.1n?arch=amd64", want: true},
		{name: "empty artifact purl fails closed", subcomponent: "pkg:npm/lodash", purl: "", want: false},
		{name: "malformed subcomponent fails closed", subcomponent: "not-a-purl", purl: "pkg:npm/lodash@1.0.0", want: false},
		{name: "malformed artifact purl fails closed", subcomponent: "pkg:npm/lodash", purl: "lodash@1.0.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, purlMatches(tt.subcomponent, tt.purl))
		})
	}
}

func TestPolicySubcomponents(t *testing.T) {
	t.Run("absent attribute is product scope", func(t *testing.T) {
		assert.Nil(t, policySubcomponents(armotypes.VulnerabilityExceptionPolicy{}))
	})

	t.Run("string slice as built in-process", func(t *testing.T) {
		p := armotypes.VulnerabilityExceptionPolicy{
			PortalBase: armotypes.PortalBase{Attributes: map[string]interface{}{attrSubcomponents: []string{"pkg:npm/lodash"}}},
		}
		assert.Equal(t, []string{"pkg:npm/lodash"}, policySubcomponents(p))
	})

	// A cloud-sourced policy has been through JSON, so its slice decodes as []interface{}.
	t.Run("interface slice as decoded from json", func(t *testing.T) {
		p := armotypes.VulnerabilityExceptionPolicy{
			PortalBase: armotypes.PortalBase{Attributes: map[string]interface{}{attrSubcomponents: []interface{}{"pkg:npm/lodash", 42}}},
		}
		assert.Equal(t, []string{"pkg:npm/lodash"}, policySubcomponents(p))
	})

	t.Run("unexpected type is product scope", func(t *testing.T) {
		p := armotypes.VulnerabilityExceptionPolicy{
			PortalBase: armotypes.PortalBase{Attributes: map[string]interface{}{attrSubcomponents: "pkg:npm/lodash"}},
		}
		assert.Nil(t, policySubcomponents(p))
	})
}

func TestNormalizedSubcomponents(t *testing.T) {
	assert.Nil(t, normalizedSubcomponents(nil))
	assert.Nil(t, normalizedSubcomponents([]string{"", "   "}), "a blank list is product scope, not an unsatisfiable scope")
	assert.Equal(t, []string{"pkg:npm/lodash"}, normalizedSubcomponents([]string{" pkg:npm/lodash ", ""}))
}

// The point of subcomponent scoping: the same CVE reported against two packages is suppressed
// only in the package the exception names.
func TestApplySecurityExceptions_SubcomponentScope(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2025-14505"}},
				Artifact:      v1beta1.GrypePackage{Name: "elliptic", Version: "6.5.4", PURL: "pkg:npm/elliptic@6.5.4"},
			},
			{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2025-14505"}},
				Artifact:      v1beta1.GrypePackage{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
			},
		},
	}

	exceptions := domain.CVEExceptions{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-2025-14505"}},
			PortalBase:            armotypes.PortalBase{Attributes: map[string]interface{}{attrSubcomponents: []string{"pkg:npm/elliptic"}}},
		},
	}

	ApplySecurityExceptions(doc, exceptions)

	require.Len(t, doc.IgnoredMatches, 1, "only the scoped package should be suppressed")
	assert.Equal(t, "elliptic", doc.IgnoredMatches[0].Artifact.Name)
	require.Len(t, doc.Matches, 1, "the unscoped package should stay visible")
	assert.Equal(t, "lodash", doc.Matches[0].Artifact.Name)
}

// Without subcomponents the exception keeps applying at product scope, so documents written
// before this field existed behave exactly as before.
func TestApplySecurityExceptions_NoSubcomponentsIsProductScope(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2025-14505"}},
				Artifact:      v1beta1.GrypePackage{Name: "elliptic", PURL: "pkg:npm/elliptic@6.5.4"},
			},
			{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2025-14505"}},
				Artifact:      v1beta1.GrypePackage{Name: "lodash", PURL: "pkg:npm/lodash@4.17.20"},
			},
		},
	}

	exceptions := domain.CVEExceptions{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-2025-14505"}},
		},
	}

	ApplySecurityExceptions(doc, exceptions)

	assert.Len(t, doc.IgnoredMatches, 2, "both packages should be suppressed at product scope")
	assert.Empty(t, doc.Matches)
}

// A match with no PURL cannot satisfy a subcomponent scope, so the finding stays visible.
func TestApplySecurityExceptions_SubcomponentScopeFailsClosedWithoutPURL(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2025-14505"}},
				Artifact:      v1beta1.GrypePackage{Name: "elliptic"},
			},
		},
	}

	exceptions := domain.CVEExceptions{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-2025-14505"}},
			PortalBase:            armotypes.PortalBase{Attributes: map[string]interface{}{attrSubcomponents: []string{"pkg:npm/elliptic"}}},
		},
	}

	ApplySecurityExceptions(doc, exceptions)

	assert.Empty(t, doc.IgnoredMatches)
	assert.Len(t, doc.Matches, 1)
}

func TestConvertCarriesSubcomponents(t *testing.T) {
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2025-14505"},
						Status:        sev1beta1.VulnerabilityStatusNotAffected,
						Subcomponents: []string{" pkg:npm/elliptic ", ""},
					},
					{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2023-44487"},
						Status:        sev1beta1.VulnerabilityStatusNotAffected,
					},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

	require.Len(t, policies, 2)
	assert.Equal(t, []string{"pkg:npm/elliptic"}, policySubcomponents(policies[0]), "scope is carried and trimmed")
	assert.Nil(t, policySubcomponents(policies[1]), "an entry without subcomponents stays product-scoped")
}
