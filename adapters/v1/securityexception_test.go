package v1

import (
	"testing"
	"time"

	sev1 "github.com/kubescape/storage/pkg/apis/securityexception/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConvertVulnerabilityExceptions(t *testing.T) {
	exceptions := []sev1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: sev1.SecurityExceptionSpec{
				Reason: "accepted risk",
				Vulnerabilities: []sev1.VulnerabilityException{
					{
						Vulnerability: sev1.VulnerabilityRef{ID: "CVE-2021-44228"},
					},
				},
			},
		},
	}
	clusterExceptions := []sev1.ClusterSecurityException{
		{
			Spec: sev1.SecurityExceptionSpec{
				Reason: "cluster-wide",
				Vulnerabilities: []sev1.VulnerabilityException{
					{
						Vulnerability: sev1.VulnerabilityRef{ID: "CVE-2022-12345"},
					},
				},
			},
		},
	}

	policies := convertToVulnerabilityExceptionPolicies(exceptions, clusterExceptions)

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
			exceptions := []sev1.SecurityException{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
					Spec: sev1.SecurityExceptionSpec{
						Vulnerabilities: []sev1.VulnerabilityException{
							{
								Vulnerability: sev1.VulnerabilityRef{ID: "CVE-2023-0001"},
								ExpiredOnFix:  tt.expiredOnFix,
							},
						},
					},
				},
			}

			policies := convertToVulnerabilityExceptionPolicies(exceptions, nil)
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

	exceptions := []sev1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1.SecurityExceptionSpec{
				ExpiresAt: &past,
				Vulnerabilities: []sev1.VulnerabilityException{
					{Vulnerability: sev1.VulnerabilityRef{ID: "CVE-EXPIRED"}},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: sev1.SecurityExceptionSpec{
				ExpiresAt: &future,
				Vulnerabilities: []sev1.VulnerabilityException{
					{Vulnerability: sev1.VulnerabilityRef{ID: "CVE-VALID"}},
				},
			},
		},
	}

	clusterExceptions := []sev1.ClusterSecurityException{
		{
			Spec: sev1.SecurityExceptionSpec{
				ExpiresAt: &past,
				Vulnerabilities: []sev1.VulnerabilityException{
					{Vulnerability: sev1.VulnerabilityRef{ID: "CVE-CLUSTER-EXPIRED"}},
				},
			},
		},
	}

	policies := convertToVulnerabilityExceptionPolicies(exceptions, clusterExceptions)

	assert.Len(t, policies, 1)
	assert.Equal(t, "CVE-VALID", policies[0].VulnerabilityPolicies[0].Name)
}

func TestConvertMatchResources(t *testing.T) {
	exceptions := []sev1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "production"},
			Spec: sev1.SecurityExceptionSpec{
				Match: sev1.ExceptionMatch{
					Resources: []sev1.ResourceMatch{
						{Kind: "Deployment", Name: "my-app"},
						{Kind: "StatefulSet", Name: "my-db"},
					},
				},
				Vulnerabilities: []sev1.VulnerabilityException{
					{Vulnerability: sev1.VulnerabilityRef{ID: "CVE-2023-9999"}},
				},
			},
		},
	}

	policies := convertToVulnerabilityExceptionPolicies(exceptions, nil)

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
