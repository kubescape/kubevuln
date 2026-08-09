package v1

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
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

func TestConvertVulnerabilityExceptions_SuppressionProvenance(t *testing.T) {
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-log4shell", Namespace: "prod"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Reason: "accepted risk",
				Match: sev1beta1.ExceptionMatch{
					Resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", Name: "web"}},
				},
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability:   sev1beta1.VulnerabilityRef{ID: "CVE-2021-44228"},
						Status:          sev1beta1.VulnerabilityStatusNotAffected,
						Justification:   "vulnerable code path is unreachable",
						ImpactStatement: "no network exposure",
					},
				},
			},
		},
	}
	clusterExceptions := []sev1beta1.ClusterSecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-cluster-wide"},
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

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, clusterExceptions, ExceptionTarget{Kind: "Deployment", Name: "web"})
	require.Len(t, policies, 2)

	nsPolicy := policies[0]
	assert.Equal(t, "allow-log4shell", nsPolicy.Name)
	assert.Equal(t, "SecurityException", nsPolicy.Attributes["sourceKind"])
	assert.Equal(t, "SecurityException/prod/allow-log4shell", nsPolicy.Attributes["ruleId"])
	assert.Equal(t, "prod", nsPolicy.Attributes["sourceNamespace"])
	assert.Equal(t, "vulnerable code path is unreachable", nsPolicy.Attributes["justification"])
	assert.Equal(t, "no network exposure", nsPolicy.Attributes["impactStatement"])
	assert.Equal(t, "prod/Deployment/web", nsPolicy.Attributes["normalizedTarget"])

	clusterPolicy := policies[1]
	assert.Equal(t, "allow-cluster-wide", clusterPolicy.Name)
	assert.Equal(t, "ClusterSecurityException", clusterPolicy.Attributes["sourceKind"])
	assert.Equal(t, "ClusterSecurityException/allow-cluster-wide", clusterPolicy.Attributes["ruleId"])
	_, hasNamespace := clusterPolicy.Attributes["sourceNamespace"]
	assert.False(t, hasNamespace, "cluster-scoped exceptions have no source namespace")
	assert.Equal(t, "cluster-wide", clusterPolicy.Attributes["normalizedTarget"])
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

	ApplySecurityExceptions(doc, exceptions, nil)

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

	ApplySecurityExceptions(doc, exceptions, nil)

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

	ApplySecurityExceptions(doc, exceptions, nil)

	assert.Len(t, doc.Matches, 1)
	assert.Equal(t, "CVE-2023-9999", doc.Matches[0].Vulnerability.ID)
	assert.Len(t, doc.IgnoredMatches, 1)
	assert.Equal(t, "GHSA-JC7W-C686-C4V9", doc.IgnoredMatches[0].Vulnerability.ID)
}

func TestApplySecurityExceptions_NilDoc(t *testing.T) {
	ApplySecurityExceptions(nil, domain.CVEExceptions{}, nil)
}

func TestApplySecurityExceptions_NoExceptions(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"}}},
		},
	}

	ApplySecurityExceptions(doc, nil, nil)

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

	ApplySecurityExceptions(doc, domain.CVEExceptions(policies), nil)

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

			ApplySecurityExceptions(doc, domain.CVEExceptions(policies), nil)

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
	ApplySecurityExceptions(doc, domain.CVEExceptions(policies), nil)

	assert.Len(t, doc.Matches, 1)
	assert.Equal(t, "CVE-2023-9999", doc.Matches[0].Vulnerability.ID)
	assert.Len(t, doc.IgnoredMatches, 1)
	assert.Equal(t, "GHSA-jfh8-c2jp-5v3q", doc.IgnoredMatches[0].Vulnerability.ID)
}

func TestApplySecurityExceptions_EmitsEventWhenRecorderConfigured(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"}},
				Artifact:      v1beta1.GrypePackage{Name: "log4j-core"},
			},
		},
	}

	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-log4shell", Namespace: "default", UID: "abc-123"},
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

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})
	require.Len(t, policies, 1)
	assert.Equal(t, "abc-123", policies[0].Attributes["sourceUID"])

	recorder := record.NewFakeRecorder(1)
	ApplySecurityExceptions(doc, domain.CVEExceptions(policies), recorder)

	require.Len(t, doc.IgnoredMatches, 1)
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, "CVE-2021-44228")
		assert.Contains(t, event, "log4j-core")
	default:
		t.Fatal("expected a suppression event to be recorded")
	}
}

func TestApplySecurityExceptions_NilRecorderIsNoOp(t *testing.T) {
	doc := &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"}}},
		},
	}
	exceptions := domain.CVEExceptions{
		{
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-2021-44228"}},
		},
	}

	assert.NotPanics(t, func() {
		ApplySecurityExceptions(doc, exceptions, nil)
	})
	assert.Len(t, doc.IgnoredMatches, 1)
}

func TestRestoreSuppressedMatches(t *testing.T) {
	t.Run("restores exception-applied ignored matches and clears IgnoredMatches", func(t *testing.T) {
		doc := &v1beta1.GrypeDocument{
			Matches: []v1beta1.Match{
				{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-KEEP"}}},
			},
			IgnoredMatches: []v1beta1.IgnoredMatch{
				{
					Match:              v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-A"}}},
					AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-A"}},
				},
				{
					Match:              v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-B"}}},
					AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-B"}},
				},
			},
		}

		restored := RestoreSuppressedMatches(doc)

		// the input document is not mutated
		assert.Len(t, doc.Matches, 1, "input document must not be mutated")
		assert.Len(t, doc.IgnoredMatches, 2, "input document must not be mutated")

		require.NotNil(t, restored)
		assert.Len(t, restored.IgnoredMatches, 0, "all exception-applied ignored matches are restored")
		require.Len(t, restored.Matches, 3)
		// existing matches are preserved first, restored matches appended after
		assert.Equal(t, "CVE-KEEP", restored.Matches[0].Vulnerability.ID)
		assert.Equal(t, "CVE-A", restored.Matches[1].Vulnerability.ID)
		assert.Equal(t, "CVE-B", restored.Matches[2].Vulnerability.ID)
	})

	t.Run("nil document returns nil", func(t *testing.T) {
		assert.Nil(t, RestoreSuppressedMatches(nil))
	})

	t.Run("no ignored matches returns the input document unchanged (no copy)", func(t *testing.T) {
		doc := &v1beta1.GrypeDocument{
			Matches: []v1beta1.Match{
				{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-1"}}},
			},
		}

		restored := RestoreSuppressedMatches(doc)

		require.NotNil(t, restored)
		assert.Same(t, doc, restored, "no ignored matches must not trigger a deep copy")
		assert.Len(t, restored.Matches, 1)
		assert.Len(t, restored.IgnoredMatches, 0)
	})

	t.Run("preserves non-exception-applied ignored matches", func(t *testing.T) {
		doc := &v1beta1.GrypeDocument{
			IgnoredMatches: []v1beta1.IgnoredMatch{
				{
					Match:              v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-A"}}},
					AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-A"}},
				},
				{
					Match:              v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-NATIVE"}}},
					AppliedIgnoreRules: []v1beta1.IgnoreRule{{Vulnerability: "CVE-NATIVE", FixState: "not-fixed"}},
				},
			},
		}

		restored := RestoreSuppressedMatches(doc)

		require.NotNil(t, restored)
		// only the exception-shaped entry is restored; the other is preserved
		assert.Len(t, restored.Matches, 1)
		assert.Equal(t, "CVE-A", restored.Matches[0].Vulnerability.ID)
		require.Len(t, restored.IgnoredMatches, 1)
		assert.Equal(t, "CVE-NATIVE", restored.IgnoredMatches[0].Match.Vulnerability.ID)
	})
}

func TestIgnoredMatchKeys(t *testing.T) {
	t.Run("collects match-identity keys for non-empty ignored IDs", func(t *testing.T) {
		doc := &v1beta1.GrypeDocument{
			IgnoredMatches: []v1beta1.IgnoredMatch{
				{Match: v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-A"}}}},
				{Match: v1beta1.Match{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: ""}}}},
			},
		}

		assert.Equal(t, map[string]struct{}{"CVE-A\x00\x00": {}}, IgnoredMatchKeys(doc))
	})

	t.Run("nil document returns an empty set", func(t *testing.T) {
		assert.Empty(t, IgnoredMatchKeys(nil))
	})
}

func TestIgnoredMatchKeys_DistinctKeysPerPackage(t *testing.T) {
	// Keys include artifact name and version so that ExpiredOnFix transitions, which can
	// suppress only some matches of a CVE, are detected (see IgnoredMatchKeys doc).
	doc := &v1beta1.GrypeDocument{
		IgnoredMatches: []v1beta1.IgnoredMatch{
			{Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"}},
				Artifact:      v1beta1.GrypePackage{Name: "log4j-api", Version: "2.17.0"},
			}},
			{Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"}},
				Artifact:      v1beta1.GrypePackage{Name: "log4j-core", Version: "2.17.0"},
			}},
			{Match: v1beta1.Match{
				Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2021-44228"}},
				Artifact:      v1beta1.GrypePackage{Name: "log4j-api", Version: "2.15.0"},
			}},
		},
	}

	assert.Equal(t, map[string]struct{}{
		"CVE-2021-44228\x00log4j-api\x002.17.0":  {},
		"CVE-2021-44228\x00log4j-core\x002.17.0": {},
		"CVE-2021-44228\x00log4j-api\x002.15.0":  {},
	}, IgnoredMatchKeys(doc))
}

func TestSuppressingPolicies_FiltersNonIgnoreActions(t *testing.T) {
	ignorePolicy := armotypes.VulnerabilityExceptionPolicy{
		PortalBase: armotypes.PortalBase{Name: "allow-log4shell"},
		Actions:    []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
	}
	alertOnlyPolicy := armotypes.VulnerabilityExceptionPolicy{
		PortalBase: armotypes.PortalBase{Name: "alert-only"},
		Actions:    []armotypes.VulnerabilityExceptionPolicyActions{"alertOnly"},
	}

	out := suppressingPolicies([]armotypes.VulnerabilityExceptionPolicy{alertOnlyPolicy, ignorePolicy})

	require.Len(t, out, 1)
	assert.Equal(t, "allow-log4shell", out[0].Name)
}

func TestConvertPerEntryExpiresAt(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	future := metav1.NewTime(time.Now().Add(1 * time.Hour))

	tests := []struct {
		name       string
		docLevel   *metav1.Time
		entry      *metav1.Time
		suppressed bool
	}{
		{name: "entry overrides an expired document", docLevel: &past, entry: &future, suppressed: true},
		{name: "entry overrides a live document", docLevel: &future, entry: &past, suppressed: false},
		{name: "entry inherits an expired document", docLevel: &past, entry: nil, suppressed: false},
		{name: "entry inherits a live document", docLevel: &future, entry: nil, suppressed: true},
		{name: "no expiry anywhere never expires", docLevel: nil, entry: nil, suppressed: true},
		{name: "entry expiry without a document default", docLevel: nil, entry: &past, suppressed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceptions := []sev1beta1.SecurityException{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
					Spec: sev1beta1.SecurityExceptionSpec{
						ExpiresAt: tt.docLevel,
						Vulnerabilities: []sev1beta1.VulnerabilityException{
							{
								Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2026-31808"},
								Status:        sev1beta1.VulnerabilityStatusNotAffected,
								ExpiresAt:     tt.entry,
							},
						},
					},
				},
			}

			policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

			if tt.suppressed {
				require.Len(t, policies, 1)
				assert.Equal(t, "CVE-2026-31808", policies[0].VulnerabilityPolicies[0].Name)
			} else {
				assert.Empty(t, policies)
			}
		})
	}
}

// A single document mixing per-entry expiries is the case that previously forced authors to
// split one review into several CRDs: the document-level check expired every entry at once.
func TestConvertPerEntryExpiresAtWithinOneDocument(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	future := metav1.NewTime(time.Now().Add(1 * time.Hour))

	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1beta1.SecurityExceptionSpec{
				ExpiresAt: &future,
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-INHERITS"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-EXPIRED-EARLY"}, Status: sev1beta1.VulnerabilityStatusNotAffected, ExpiresAt: &past},
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-EXTENDED"}, Status: sev1beta1.VulnerabilityStatusFixed, ExpiresAt: &future},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

	require.Len(t, policies, 2)
	assert.Equal(t, "CVE-INHERITS", policies[0].VulnerabilityPolicies[0].Name)
	assert.Equal(t, "CVE-EXTENDED", policies[1].VulnerabilityPolicies[0].Name)
}

func TestConvertPerEntryExpiresAtClusterScoped(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	future := metav1.NewTime(time.Now().Add(1 * time.Hour))

	clusterExceptions := []sev1beta1.ClusterSecurityException{
		{
			Spec: sev1beta1.SecurityExceptionSpec{
				ExpiresAt: &past,
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-CLUSTER-EXPIRED"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-CLUSTER-EXTENDED"}, Status: sev1beta1.VulnerabilityStatusNotAffected, ExpiresAt: &future},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(nil, clusterExceptions, ExceptionTarget{})

	require.Len(t, policies, 1)
	assert.Equal(t, "CVE-CLUSTER-EXTENDED", policies[0].VulnerabilityPolicies[0].Name)
}

// The policy handed downstream must carry the same expiry the suppression decision used,
// otherwise a per-entry override would be dropped on the way to the backend.
func TestConvertPerEntryExpiresAtSetsExpirationDate(t *testing.T) {
	docLevel := metav1.NewTime(time.Now().Add(1 * time.Hour))
	entryLevel := metav1.NewTime(time.Now().Add(48 * time.Hour))

	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1beta1.SecurityExceptionSpec{
				ExpiresAt: &docLevel,
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-INHERITS"}, Status: sev1beta1.VulnerabilityStatusNotAffected},
					{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-OVERRIDES"}, Status: sev1beta1.VulnerabilityStatusNotAffected, ExpiresAt: &entryLevel},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

	require.Len(t, policies, 2)
	require.NotNil(t, policies[0].ExpirationDate)
	assert.Equal(t, docLevel.Time, *policies[0].ExpirationDate)
	require.NotNil(t, policies[1].ExpirationDate)
	assert.Equal(t, entryLevel.Time, *policies[1].ExpirationDate)
}

// affected is the one status whose suppression depends on more than the status itself, so
// the matrix below is the contract: an actionStatement plus a response that says no
// remediation is coming, and nothing less.
func TestConvertAffectedSuppression(t *testing.T) {
	tests := []struct {
		name            string
		actionStatement string
		response        []sev1beta1.VulnerabilityResponse
		wantSuppressed  bool
	}{
		{
			name:            "will_not_fix with an action statement is an accepted risk",
			actionStatement: "WAF blocks the exploit vector, reviewed by security lead",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseWillNotFix},
			wantSuppressed:  true,
		},
		{
			name:            "can_not_fix with an action statement is an accepted risk",
			actionStatement: "no upstream fix available",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseCanNotFix},
			wantSuppressed:  true,
		},
		{
			name:            "both non-remediating responses together",
			actionStatement: "no upstream fix and none planned",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseCanNotFix, sev1beta1.VulnerabilityResponseWillNotFix},
			wantSuppressed:  true,
		},
		{
			name:            "update keeps the finding visible until the fix lands",
			actionStatement: "upgrade scheduled for the Q4 release",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseUpdate},
			wantSuppressed:  false,
		},
		{
			name:            "rollback keeps the finding visible",
			actionStatement: "rolling back to 1.2.3",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseRollback},
			wantSuppressed:  false,
		},
		{
			name:            "workaround_available keeps the finding visible",
			actionStatement: "config workaround applied",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseWorkaroundAvailable},
			wantSuppressed:  false,
		},
		{
			name:            "a remediating response alongside will_not_fix still tracks work",
			actionStatement: "not fixing now, upgrade planned later",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseWillNotFix, sev1beta1.VulnerabilityResponseUpdate},
			wantSuppressed:  false,
		},
		{
			name:            "no response is no suppression signal",
			actionStatement: "under discussion with the vendor",
			response:        nil,
			wantSuppressed:  false,
		},
		{
			name:            "will_not_fix without an action statement is not a valid affected statement",
			actionStatement: "",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseWillNotFix},
			wantSuppressed:  false,
		},
		{
			name:            "a blank action statement does not count",
			actionStatement: "   ",
			response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseWillNotFix},
			wantSuppressed:  false,
		},
		{
			name:            "an unrecognised response value suppresses nothing",
			actionStatement: "accepted",
			response:        []sev1beta1.VulnerabilityResponse{"risk_accepted"},
			wantSuppressed:  false,
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
								Vulnerability:   sev1beta1.VulnerabilityRef{ID: "CVE-2021-44228"},
								Status:          sev1beta1.VulnerabilityStatusAffected,
								ActionStatement: tt.actionStatement,
								Response:        tt.response,
							},
						},
					},
				},
			}

			policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

			if tt.wantSuppressed {
				require.Len(t, policies, 1)
				assert.Equal(t, "CVE-2021-44228", policies[0].VulnerabilityPolicies[0].Name)
			} else {
				assert.Empty(t, policies)
			}
		})
	}
}

// The statuses that resolve a CVE keep suppressing on the status alone, so documents written
// before affected existed are unaffected by the new rules.
func TestConvertResolvingStatusesUnchangedByAffected(t *testing.T) {
	for _, status := range []sev1beta1.VulnerabilityStatus{
		sev1beta1.VulnerabilityStatusNotAffected,
		sev1beta1.VulnerabilityStatusFixed,
	} {
		t.Run(string(status), func(t *testing.T) {
			exceptions := []sev1beta1.SecurityException{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
					Spec: sev1beta1.SecurityExceptionSpec{
						Vulnerabilities: []sev1beta1.VulnerabilityException{
							{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2021-44228"}, Status: status},
						},
					},
				},
			}

			policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

			require.Len(t, policies, 1, "no actionStatement or response should be needed")
		})
	}
}

func TestConvertAffectedRecordsProvenance(t *testing.T) {
	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "risk-accepted-log4j", Namespace: "ns"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability:   sev1beta1.VulnerabilityRef{ID: "CVE-2021-44228"},
						Status:          sev1beta1.VulnerabilityStatusAffected,
						ActionStatement: "WAF mitigation in place, ticket SEC-1234",
						Response:        []sev1beta1.VulnerabilityResponse{sev1beta1.VulnerabilityResponseWillNotFix},
					},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

	require.Len(t, policies, 1)
	assert.Equal(t, "WAF mitigation in place, ticket SEC-1234", policies[0].Attributes["actionStatement"])
	assert.Equal(t, []string{"will_not_fix"}, policies[0].Attributes["response"])
}
