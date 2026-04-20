package v1

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConvertVulnerabilityExceptions(t *testing.T) {
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Reason: "accepted risk",
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2021-44228"},
					},
				},
			},
		},
	}
	clusterExceptions := []sev1beta1.ClusterSecurityException{
		{
			Spec: sev1beta1.SecurityExceptionSpec{
				Reason: "cluster-wide",
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2022-12345"},
					},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, clusterExceptions)

	assert.Len(t, policies, 2)

	// Namespaced exception
	assert.Equal(t, "vulnerabilityExceptionPolicy", policies[0].PolicyType)
	assert.Equal(t, "CVE-2021-44228", policies[0].VulnerabilityPolicies[0].Name)
	assert.Equal(t, "accepted risk", policies[0].Reason)
	assert.Len(t, policies[0].Actions, 1)
	assert.Equal(t, "ignore", string(policies[0].Actions[0]))
	// Should have namespace-only designator
	assert.Len(t, policies[0].Designatores, 1)
	assert.Equal(t, "default", policies[0].Designatores[0].Attributes["namespace"])

	// Cluster exception
	assert.Equal(t, "CVE-2022-12345", policies[1].VulnerabilityPolicies[0].Name)
	assert.Equal(t, "cluster-wide", policies[1].Reason)
	// No namespace, no resources => nil designators
	assert.Nil(t, policies[1].Designatores)
}

func TestConvertExpiredOnFix(t *testing.T) {
	tests := []struct {
		name         string
		expiredOnFix bool
		wantNil      bool
		wantValue    bool
	}{
		{
			name:         "true sets pointer to true",
			expiredOnFix: true,
			wantNil:      false,
			wantValue:    true,
		},
		{
			name:         "false leaves pointer nil",
			expiredOnFix: false,
			wantNil:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceptions := []sev1beta1.SecurityException{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
					Spec: sev1beta1.SecurityExceptionSpec{
						Vulnerabilities: []sev1beta1.VulnerabilityException{
							{
								Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2023-0001"},
								ExpiredOnFix:  tt.expiredOnFix,
							},
						},
					},
				},
			}

			policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil)
			assert.Len(t, policies, 1)

			if tt.wantNil {
				assert.Nil(t, policies[0].ExpiredOnFix)
			} else {
				assert.NotNil(t, policies[0].ExpiredOnFix)
				assert.Equal(t, tt.wantValue, *policies[0].ExpiredOnFix)
			}
		})
	}
}

func TestConvertSkipsExpired(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	future := metav1.NewTime(time.Now().Add(1 * time.Hour))

	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1beta1.SecurityExceptionSpec{
				ExpiresAt: &past,
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-EXPIRED"}},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1beta1.SecurityExceptionSpec{
				ExpiresAt: &future,
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-VALID"}},
				},
			},
		},
	}

	clusterExceptions := []sev1beta1.ClusterSecurityException{
		{
			Spec: sev1beta1.SecurityExceptionSpec{
				ExpiresAt: &past,
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-CLUSTER-EXPIRED"}},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, clusterExceptions)

	assert.Len(t, policies, 1)
	assert.Equal(t, "CVE-VALID", policies[0].VulnerabilityPolicies[0].Name)
}

func TestConvertMatchResources(t *testing.T) {
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "production"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Match: sev1beta1.ExceptionMatch{
					Resources: []sev1beta1.ResourceMatch{
						{Kind: "Deployment", Name: "my-app"},
						{Kind: "StatefulSet", Name: "my-db"},
					},
				},
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2023-9999"}},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil)

	assert.Len(t, policies, 1)
	assert.Len(t, policies[0].Designatores, 2)

	d0 := policies[0].Designatores[0]
	assert.Equal(t, "production", d0.Attributes["namespace"])
	assert.Equal(t, "Deployment", d0.Attributes["kind"])
	assert.Equal(t, "my-app", d0.Attributes["name"])

	d1 := policies[0].Designatores[1]
	assert.Equal(t, "production", d1.Attributes["namespace"])
	assert.Equal(t, "StatefulSet", d1.Attributes["kind"])
	assert.Equal(t, "my-db", d1.Attributes["name"])
}

func TestApplySecurityExceptions_MovesToIgnored(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"}}},
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2023-9999"}}},
		},
	}

	exceptions := domain.CVEExceptions{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-2021-44228"}},
		},
	}

	ApplySecurityExceptions(doc, exceptions)

	assert.Len(t, doc.Matches, 1, "one match should remain")
	assert.Equal(t, "CVE-2023-9999", doc.Matches[0].Vulnerability.ID)

	assert.Len(t, doc.IgnoredMatches, 1, "one match should be ignored")
	assert.Equal(t, "CVE-2021-44228", doc.IgnoredMatches[0].Vulnerability.ID)
	assert.Len(t, doc.IgnoredMatches[0].AppliedIgnoreRules, 1)
	assert.Equal(t, "CVE-2021-44228", doc.IgnoredMatches[0].AppliedIgnoreRules[0].Vulnerability)
}

func TestApplySecurityExceptions_ExpiredOnFix(t *testing.T) {
	expiredOnFix := true
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{
				VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"},
				Fix:                   v1beta1.Fix{State: "fixed", Versions: []string{"2.17.0"}},
			}},
		},
	}

	exceptions := domain.CVEExceptions{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-2021-44228"}},
			ExpiredOnFix:          &expiredOnFix,
		},
	}

	ApplySecurityExceptions(doc, exceptions)

	// Fix available + expiredOnFix = exception skipped, CVE stays in Matches
	assert.Len(t, doc.Matches, 1, "CVE with fix should remain in Matches when expiredOnFix is set")
	assert.Len(t, doc.IgnoredMatches, 0, "nothing should be ignored when fix is available and expiredOnFix is set")
}

func TestConvertSkipsEmptyAndWhitespaceIDs(t *testing.T) {
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: ""}},
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "   "}},
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "  CVE-2024-1234  "}},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil)

	assert.Len(t, policies, 1)
	assert.Equal(t, "CVE-2024-1234", policies[0].VulnerabilityPolicies[0].Name)
}

func TestApplySecurityExceptions_CaseInsensitive(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "GHSA-JC7W-C686-C4V9"}}},
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2023-9999"}}},
		},
	}

	// Exception stored with mixed-case GHSA ID (canonical form from CRD)
	exceptions := domain.CVEExceptions{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "GHSA-jc7w-c686-c4v9"}},
		},
	}

	ApplySecurityExceptions(doc, exceptions)

	assert.Len(t, doc.Matches, 1)
	assert.Equal(t, "CVE-2023-9999", doc.Matches[0].Vulnerability.ID)
	assert.Len(t, doc.IgnoredMatches, 1)
	assert.Equal(t, "GHSA-JC7W-C686-C4V9", doc.IgnoredMatches[0].Vulnerability.ID)
}

func TestApplySecurityExceptions_NilDoc(t *testing.T) {
	ApplySecurityExceptions(nil, domain.CVEExceptions{})
}

func TestApplySecurityExceptions_NoExceptions(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"}}},
		},
	}

	ApplySecurityExceptions(doc, nil)

	assert.Len(t, doc.Matches, 1, "no filtering when no exceptions")
}
