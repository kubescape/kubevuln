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
						Status:        sev1beta1.VulnerabilityStatusNotAffected,
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
						Status:        sev1beta1.VulnerabilityStatusNotAffected,
					},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, clusterExceptions, ExceptionTarget{})

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
								Status:        sev1beta1.VulnerabilityStatusNotAffected,
								ExpiredOnFix:  tt.expiredOnFix,
							},
						},
					},
				},
			}

			policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})
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
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-EXPIRED"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1beta1.SecurityExceptionSpec{
				ExpiresAt: &future,
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-VALID"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
				},
			},
		},
	}

	clusterExceptions := []sev1beta1.ClusterSecurityException{
		{
			Spec: sev1beta1.SecurityExceptionSpec{
				ExpiresAt: &past,
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-CLUSTER-EXPIRED"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, clusterExceptions, ExceptionTarget{})

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
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2023-9999"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
				},
			},
		},
	}

	// target matches the first resource entry (Deployment/my-app)
	target := ExceptionTarget{Namespace: "production", Kind: "Deployment", Name: "my-app"}
	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, target)

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

// TestConvertShouldSuppressAllowlist verifies the allowlist semantics of shouldSuppress:
// only not_affected and fixed produce a suppression policy; everything else
// (empty, under_investigation, unrecognised values, blank IDs) does not.
func TestConvertShouldSuppressAllowlist(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		status       sev1beta1.VulnerabilityStatus
		wantPolicies int
		wantName     string // non-empty: assert the emitted policy name equals this value
	}{
		{name: "empty ID is skipped", id: "", status: sev1beta1.VulnerabilityStatusNotAffected, wantPolicies: 0},
		{name: "whitespace ID is skipped", id: "   ", status: sev1beta1.VulnerabilityStatusNotAffected, wantPolicies: 0},
		{name: "not_affected suppresses", id: "CVE-2024-0001", status: sev1beta1.VulnerabilityStatusNotAffected, wantPolicies: 1},
		{name: "fixed suppresses", id: "CVE-2024-0002", status: sev1beta1.VulnerabilityStatusFixed, wantPolicies: 1},
		{name: "under_investigation does not suppress", id: "CVE-2024-0003", status: sev1beta1.VulnerabilityStatusUnderInvestigation, wantPolicies: 0},
		{name: "empty status does not suppress", id: "CVE-2024-0004", status: "", wantPolicies: 0},
		{name: "unrecognised status does not suppress", id: "CVE-2024-0005", status: "typo", wantPolicies: 0},
		// Guards strings.TrimSpace inside buildPolicy (regression from 6784e9b).
		{name: "padded ID is trimmed in policy name", id: "  CVE-2024-1234  ", status: sev1beta1.VulnerabilityStatusNotAffected, wantPolicies: 1, wantName: "CVE-2024-1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceptions := []sev1beta1.SecurityException{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
					Spec: sev1beta1.SecurityExceptionSpec{
						Vulnerabilities: []sev1beta1.VulnerabilityException{
							{Vulnerability: sev1beta1.VulnerabilityRef{ID: tt.id}, Status: tt.status},
						},
					},
				},
			}
			policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})
			assert.Len(t, policies, tt.wantPolicies, "status=%q id=%q", tt.status, tt.id)
			if tt.wantName != "" {
				assert.Equal(t, tt.wantName, policies[0].VulnerabilityPolicies[0].Name, "policy name should be trimmed")
			}
		})
	}
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

// TestConvertMixedStatusException verifies that within a single SecurityException,
// an under_investigation entry stays visible while a not_affected entry is suppressed.
// This is the critical regression case: it proves the per-entry filter is correct and
// not accidentally dropping the whole exception object.
func TestConvertMixedStatusException(t *testing.T) {
	const underInvestigationID = "CVE-2023-11111"
	const notAffectedID = "CVE-2023-22222"
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: underInvestigationID},
						Status:        sev1beta1.VulnerabilityStatusUnderInvestigation,
					},
					{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: notAffectedID},
						Status:        sev1beta1.VulnerabilityStatusNotAffected,
					},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

	// Only not_affected produces a policy; under_investigation must not.
	assert.Len(t, policies, 1)
	assert.Equal(t, notAffectedID, policies[0].VulnerabilityPolicies[0].Name)

	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: underInvestigationID}}},
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: notAffectedID}}},
		},
	}

	ApplySecurityExceptions(doc, domain.CVEExceptions(policies))

	// under_investigation stays in Matches.
	assert.Len(t, doc.Matches, 1)
	assert.Equal(t, underInvestigationID, doc.Matches[0].Vulnerability.ID)

	// not_affected moves to IgnoredMatches.
	assert.Len(t, doc.IgnoredMatches, 1)
	assert.Equal(t, notAffectedID, doc.IgnoredMatches[0].Vulnerability.ID)
}

// TestUnderInvestigationDoesNotSuppress is a table-driven regression test covering
// both namespaced (SecurityException) and cluster-scoped (ClusterSecurityException)
// paths, replacing the standalone under_investigation_regression_test.go file.
func TestUnderInvestigationDoesNotSuppress(t *testing.T) {
	const vulnerabilityID = "CVE-2023-44487"

	tests := []struct {
		name       string
		namespaced bool
	}{
		{name: "namespaced SecurityException", namespaced: true},
		{name: "cluster-scoped ClusterSecurityException", namespaced: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := []sev1beta1.VulnerabilityException{
				{
					Vulnerability: sev1beta1.VulnerabilityRef{ID: vulnerabilityID},
					Status:        sev1beta1.VulnerabilityStatusUnderInvestigation,
				},
			}

			var policies []armotypes.VulnerabilityExceptionPolicy
			if tt.namespaced {
				exceptions := []sev1beta1.SecurityException{
					{
						ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
						Spec:       sev1beta1.SecurityExceptionSpec{Vulnerabilities: vulns},
					},
				}
				policies = ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})
			} else {
				clusterExceptions := []sev1beta1.ClusterSecurityException{
					{
						Spec: sev1beta1.SecurityExceptionSpec{Vulnerabilities: vulns},
					},
				}
				policies = ConvertToVulnerabilityExceptionPolicies(nil, clusterExceptions, ExceptionTarget{})
			}

			assert.Empty(t, policies, "under_investigation must not produce a suppression policy")

			doc := &v1beta1.GrypeDocument{
				Matches: []v1beta1.Match{
					{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: vulnerabilityID}}},
				},
			}

			ApplySecurityExceptions(doc, domain.CVEExceptions(policies))

			assert.Len(t, doc.Matches, 1, "under_investigation CVE must remain in Matches")
			assert.Empty(t, doc.IgnoredMatches, "under_investigation CVE must not appear in IgnoredMatches")
		})
	}
}

func TestConvertVulnerabilityExceptions_Aliases(t *testing.T) {
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability: sev1beta1.VulnerabilityRef{
							ID:      "CVE-2021-44228",
							Aliases: []string{"GHSA-jfh8-c2jp-5v3q", "  GHSA-xxxx-xxxx-xxxx  ", ""},
						},
						Status: sev1beta1.VulnerabilityStatusNotAffected,
					},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

	assert.Len(t, policies, 1)
	names := make([]string, 0, len(policies[0].VulnerabilityPolicies))
	for _, vp := range policies[0].VulnerabilityPolicies {
		names = append(names, vp.Name)
	}
	assert.Equal(t, []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "GHSA-xxxx-xxxx-xxxx"}, names)
}

func TestApplySecurityExceptions_MatchesByAlias(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "GHSA-jfh8-c2jp-5v3q"}}},
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2023-9999"}}},
		},
	}

	// CRD declares the CVE as primary ID and the GHSA grype reports as an alias
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability: sev1beta1.VulnerabilityRef{
							ID:      "CVE-2021-44228",
							Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
						},
						Status: sev1beta1.VulnerabilityStatusNotAffected,
					},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})
	ApplySecurityExceptions(doc, domain.CVEExceptions(policies))

	assert.Len(t, doc.Matches, 1)
	assert.Equal(t, "CVE-2023-9999", doc.Matches[0].Vulnerability.ID)
	assert.Len(t, doc.IgnoredMatches, 1)
	assert.Equal(t, "GHSA-jfh8-c2jp-5v3q", doc.IgnoredMatches[0].Vulnerability.ID)
}
