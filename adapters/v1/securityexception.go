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
//
// Only exceptions whose spec.match applies to target are converted, so an
// exception scoped by resources/images/objectSelector/namespaceSelector is not
// applied to workloads it does not target. Expired exceptions are skipped.
func ConvertToVulnerabilityExceptionPolicies(exceptions []sev1beta1.SecurityException, clusterExceptions []sev1beta1.ClusterSecurityException, target ExceptionTarget) []armotypes.VulnerabilityExceptionPolicy {
	var policies []armotypes.VulnerabilityExceptionPolicy

	now := time.Now()

	for i := range exceptions {
		se := &exceptions[i]
		if isExpired(se.Spec.ExpiresAt, now) {
			continue
		}
		if !matchExceptionTarget(se.Spec.Match, target, false) {
			continue
		}
		namespace := se.Namespace
		for _, vuln := range se.Spec.Vulnerabilities {
			if !shouldSuppress(vuln) {
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
		if !matchExceptionTarget(cse.Spec.Match, target, true) {
			continue
		}
		for _, vuln := range cse.Spec.Vulnerabilities {
			if !shouldSuppress(vuln) {
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

// shouldSuppress reports whether a VulnerabilityException entry may be
// converted into an ignore policy.
//
// The allowlist approach (fail-closed): only the two VEX statuses that
// definitively resolve a CVE – not_affected and fixed – produce a
// suppression policy. Every other value, including the empty string,
// under_investigation, and any future status that is not yet in the
// enum, leaves the finding visible in the scan results.
func shouldSuppress(vuln sev1beta1.VulnerabilityException) bool {
	if strings.TrimSpace(vuln.Vulnerability.ID) == "" {
		return false
	}
	switch vuln.Status {
	case sev1beta1.VulnerabilityStatusNotAffected, sev1beta1.VulnerabilityStatusFixed:
		return true
	default:
		return false
	}
}

func buildPolicy(spec sev1beta1.SecurityExceptionSpec, vuln sev1beta1.VulnerabilityException, namespace string) armotypes.VulnerabilityExceptionPolicy {
	vulnerabilityPolicies := []armotypes.VulnerabilityPolicy{
		{Name: strings.TrimSpace(vuln.Vulnerability.ID)},
	}
	for _, alias := range vuln.Vulnerability.Aliases {
		if a := strings.TrimSpace(alias); a != "" {
			vulnerabilityPolicies = append(vulnerabilityPolicies, armotypes.VulnerabilityPolicy{Name: a})
		}
	}

	p := armotypes.VulnerabilityExceptionPolicy{
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: vulnerabilityPolicies,
		Reason:                spec.Reason,
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

// RestoreSuppressedMatches is the inverse of ApplySecurityExceptions: it returns a copy of doc
// with exception-applied ignored matches moved back into Matches, reconstructing the original
// unfiltered manifest so a cached (filtered) manifest can be re-evaluated against the current
// SecurityException set. The input document is not mutated, mirroring ApplySecurityExceptions'
// copy semantics. When there is nothing to restore, the input document is returned unchanged —
// the only caller hands the result to applyExceptionsToManifest, which copies before mutating,
// so the shared stored object is never modified.
//
// Only ignored matches carrying the signature ApplySecurityExceptions writes (a single ignore
// rule with only the vulnerability ID set) are restored. Any other entry (e.g. one that would be
// produced if GrypeAdapter ever wired up IgnoreRules/VexProcessor) is preserved, so the helper is
// self-guarding instead of relying on an assumption. Reconstruction is lossless because
// IgnoredMatch embeds the full Match.
func RestoreSuppressedMatches(doc *v1beta1.GrypeDocument) *v1beta1.GrypeDocument {
	if doc == nil {
		return nil
	}
	if len(doc.IgnoredMatches) == 0 {
		return doc
	}
	restored := doc.DeepCopy()
	var kept []v1beta1.IgnoredMatch
	for _, im := range restored.IgnoredMatches {
		if isExceptionSourcedIgnore(im) {
			restored.Matches = append(restored.Matches, im.Match)
		} else {
			kept = append(kept, im)
		}
	}
	restored.IgnoredMatches = kept
	return restored
}

// isExceptionSourcedIgnore reports whether an ignored match carries the AppliedIgnoreRules
// signature ApplySecurityExceptions writes: exactly one rule whose only field is the
// vulnerability ID.
func isExceptionSourcedIgnore(im v1beta1.IgnoredMatch) bool {
	if len(im.AppliedIgnoreRules) != 1 {
		return false
	}
	r := im.AppliedIgnoreRules[0]
	return r.FixState == "" && r.Package == nil
}

// IgnoredMatchKeys returns the set of match-identity keys for a manifest's ignored matches.
// Keyed by vulnerability ID + artifact name + version (via \x00 separators) rather than CVE ID
// alone, because an ExpiredOnFix policy suppresses only the matches of a CVE whose
// Fix.State != "fixed" (getCVEExceptionMatchCVENameFromList), so two matches of the same CVE can
// have different suppression states. The manifest content is fixed across a cache hit, so these
// keys are stable and detect both ID- and fix-state-driven changes to the ignored set.
func IgnoredMatchKeys(doc *v1beta1.GrypeDocument) map[string]struct{} {
	keys := map[string]struct{}{}
	if doc == nil {
		return keys
	}
	for _, im := range doc.IgnoredMatches {
		m := im.Match
		if m.Vulnerability.ID != "" {
			keys[m.Vulnerability.ID+"\x00"+m.Artifact.Name+"\x00"+m.Artifact.Version] = struct{}{}
		}
	}
	return keys
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
