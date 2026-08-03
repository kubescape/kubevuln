package v1

import (
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUnderInvestigationSecurityExceptionDoesNotSuppress(t *testing.T) {
	const vulnerabilityID = "CVE-2023-44487"

	exceptions := []sev1beta1.SecurityException{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Vulnerabilities: []sev1beta1.VulnerabilityException{
					{
						Vulnerability: sev1beta1.VulnerabilityRef{ID: vulnerabilityID},
						Status:        sev1beta1.VulnerabilityStatusUnderInvestigation,
					},
				},
			},
		},
	}

	policies := ConvertToVulnerabilityExceptionPolicies(exceptions, nil, ExceptionTarget{})

	doc := &storagev1beta1.GrypeDocument{
		Matches: []storagev1beta1.Match{
			{
				Vulnerability: storagev1beta1.Vulnerability{
					VulnerabilityMetadata: storagev1beta1.VulnerabilityMetadata{
						ID: vulnerabilityID,
					},
				},
			},
		},
	}

	ApplySecurityExceptions(doc, domain.CVEExceptions(policies))

	require.Len(t, doc.Matches, 1)
	require.Empty(t, doc.IgnoredMatches)
}
