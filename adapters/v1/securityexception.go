package v1

import (
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConvertToVulnerabilityExceptionPolicies converts SecurityException and
// ClusterSecurityException CRDs into armotypes.VulnerabilityExceptionPolicy
// slices compatible with the existing exception pipeline.
func ConvertToVulnerabilityExceptionPolicies(exceptions []sev1beta1.SecurityException, clusterExceptions []sev1beta1.ClusterSecurityException) []armotypes.VulnerabilityExceptionPolicy {
	var policies []armotypes.VulnerabilityExceptionPolicy

	now := time.Now()

	for i := range exceptions {
		se := &exceptions[i]
		if isExpired(se.Spec.ExpiresAt, now) {
			continue
		}
		namespace := se.Namespace
		for _, vuln := range se.Spec.Vulnerabilities {
			if strings.TrimSpace(vuln.Vulnerability.ID) == "" {
				continue
			}
			p := buildPolicy(se.Spec, vuln, namespace)
			policies = append(policies, p)
		}
	}

	for i := range clusterExceptions {
		cse := &clusterExceptions[i]
		if isExpired(cse.Spec.ExpiresAt, now) {
			continue
		}
		for _, vuln := range cse.Spec.Vulnerabilities {
			if strings.TrimSpace(vuln.Vulnerability.ID) == "" {
				continue
			}
			p := buildPolicy(cse.Spec, vuln, "")
			policies = append(policies, p)
		}
	}

	return policies
}

func isExpired(expiresAt *metav1.Time, now time.Time) bool {
	return expiresAt != nil && expiresAt.Time.Before(now)
}

func buildPolicy(spec sev1beta1.SecurityExceptionSpec, vuln sev1beta1.VulnerabilityException, namespace string) armotypes.VulnerabilityExceptionPolicy {
	p := armotypes.VulnerabilityExceptionPolicy{
		PolicyType: "vulnerabilityExceptionPolicy",
		Actions:    []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
			{Name: strings.TrimSpace(vuln.Vulnerability.ID)},
		},
		Reason: spec.Reason,
	}

	if spec.ExpiresAt != nil {
		t := spec.ExpiresAt.Time
		p.ExpirationDate = &t
	}

	if vuln.ExpiredOnFix {
		b := true
		p.ExpiredOnFix = &b
	}

	p.Designatores = buildDesignators(spec.Match.Resources, namespace)

	return p
}

// hasIgnoreAction returns true if any of the matched policies contain the Ignore action.
func hasIgnoreAction(policies []armotypes.VulnerabilityExceptionPolicy) bool {
	for _, p := range policies {
		for _, a := range p.Actions {
			if a == armotypes.Ignore {
				return true
			}
		}
	}
	return false
}

// ApplySecurityExceptions moves CVEs covered by exception policies from
// doc.Matches to doc.IgnoredMatches with applied ignore rules.
func ApplySecurityExceptions(doc *v1beta1.GrypeDocument, exceptions domain.CVEExceptions) {
	if doc == nil || len(exceptions) == 0 {
		return
	}

	var remaining []v1beta1.Match
	for _, m := range doc.Matches {
		isFixed := m.Vulnerability.Fix.State == "fixed"
		matched := getCVEExceptionMatchCVENameFromList(exceptions, m.Vulnerability.ID, isFixed)
		if len(matched) > 0 && hasIgnoreAction(matched) {
			doc.IgnoredMatches = append(doc.IgnoredMatches, v1beta1.IgnoredMatch{
				Match: m,
				AppliedIgnoreRules: []v1beta1.IgnoreRule{
					{Vulnerability: m.Vulnerability.ID},
				},
			})
		} else {
			remaining = append(remaining, m)
		}
	}
	doc.Matches = remaining
}

func buildDesignators(resources []sev1beta1.ResourceMatch, namespace string) []identifiers.PortalDesignator {
	if len(resources) == 0 {
		// No specific resource match — create a namespace-only designator
		if namespace != "" {
			return []identifiers.PortalDesignator{
				{
					DesignatorType: identifiers.DesignatorAttributes,
					Attributes: map[string]string{
						"namespace": namespace,
					},
				},
			}
		}
		return nil
	}

	designators := make([]identifiers.PortalDesignator, 0, len(resources))
	for _, r := range resources {
		attrs := map[string]string{}
		if namespace != "" {
			attrs["namespace"] = namespace
		}
		if r.Kind != "" {
			attrs["kind"] = r.Kind
		}
		if r.Name != "" {
			attrs["name"] = r.Name
		}
		if len(attrs) == 0 {
			continue
		}
		designators = append(designators, identifiers.PortalDesignator{
			DesignatorType: identifiers.DesignatorAttributes,
			Attributes:     attrs,
		})
	}
	return designators
}
