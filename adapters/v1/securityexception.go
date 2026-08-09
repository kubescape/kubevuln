package v1

import (
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

// securityExceptionAPIVersion is the apiVersion recorded on the ObjectReference used
// when emitting suppression Events, matching pkg/securityexception/v1beta1's group/version.
const securityExceptionAPIVersion = "kubescape.io/v1beta1"

// suppressionSource identifies the CRD object a suppression provenance record originated
// from, so a suppressed CVE can be traced back to the exception (and its scope) that
// caused it to be filtered out of scan results.
type suppressionSource struct {
	kind      string // "SecurityException" or "ClusterSecurityException"
	name      string
	namespace string
	uid       types.UID
}

// ConvertToVulnerabilityExceptionPolicies converts SecurityException and
// ClusterSecurityException CRDs into armotypes.VulnerabilityExceptionPolicy
// slices compatible with the existing exception pipeline.
//
// Only exceptions whose spec.match applies to target are converted, so an
// exception scoped by resources/images/objectSelector/namespaceSelector is not
// applied to workloads it does not target. Expired vulnerability entries (see
// effectiveExpiresAt) are skipped, and counted in the returned
// domain.ExceptionStats.ExpiredBySource.
func ConvertToVulnerabilityExceptionPolicies(exceptions []sev1beta1.SecurityException, clusterExceptions []sev1beta1.ClusterSecurityException, target ExceptionTarget) ([]armotypes.VulnerabilityExceptionPolicy, domain.ExceptionStats) {
	var policies []armotypes.VulnerabilityExceptionPolicy
	stats := domain.ExceptionStats{ExpiredBySource: map[string]int{}}

	now := time.Now()

	for i := range exceptions {
		se := &exceptions[i]
		if !matchExceptionTarget(se.Spec.Match, target, false) {
			continue
		}
		namespace := se.Namespace
		for _, vuln := range se.Spec.Vulnerabilities {
			if !shouldSuppress(vuln) {
				continue
			}
			if isExpired(effectiveExpiresAt(se.Spec, vuln), now) {
				stats.ExpiredBySource["SecurityException"]++
				continue
			}
			p := buildPolicy(se.Spec, vuln, namespace, suppressionSource{
				kind:      "SecurityException",
				name:      se.Name,
				namespace: se.Namespace,
				uid:       se.UID,
			})
			policies = append(policies, p)
		}
	}

	for i := range clusterExceptions {
		cse := &clusterExceptions[i]
		if !matchExceptionTarget(cse.Spec.Match, target, true) {
			continue
		}
		for _, vuln := range cse.Spec.Vulnerabilities {
			if !shouldSuppress(vuln) {
				continue
			}
			if isExpired(effectiveExpiresAt(cse.Spec, vuln), now) {
				stats.ExpiredBySource["ClusterSecurityException"]++
				continue
			}
			p := buildPolicy(cse.Spec, vuln, "", suppressionSource{
				kind: "ClusterSecurityException",
				name: cse.Name,
				uid:  cse.UID,
			})
			policies = append(policies, p)
		}
	}

	return policies, stats
}

func isExpired(expiresAt *metav1.Time, now time.Time) bool {
	return expiresAt != nil && expiresAt.Time.Before(now)
}

// effectiveExpiresAt resolves the expiry governing a single vulnerability entry: the
// per-entry expiresAt when set, otherwise the document-level default.
//
// Expiry is therefore decided per entry rather than per document. A document-level
// expiresAt still expires every entry that does not override it, so documents written
// before per-entry expiry existed behave exactly as they did before.
func effectiveExpiresAt(spec sev1beta1.SecurityExceptionSpec, vuln sev1beta1.VulnerabilityException) *metav1.Time {
	if vuln.ExpiresAt != nil {
		return vuln.ExpiresAt
	}
	return spec.ExpiresAt
}

// shouldSuppress reports whether a VulnerabilityException entry may be
// converted into an ignore policy.
//
// The allowlist approach (fail-closed): only the two VEX statuses that
// definitively resolve a CVE, not_affected and fixed, suppress on the status
// alone. An affected entry suppresses only when it also states that no
// remediation is coming (see affectedSuppresses). Every other value, including
// the empty string, under_investigation, and any future status that is not yet
// in the enum, leaves the finding visible in the scan results.
func shouldSuppress(vuln sev1beta1.VulnerabilityException) bool {
	if strings.TrimSpace(vuln.Vulnerability.ID) == "" {
		return false
	}
	switch vuln.Status {
	case sev1beta1.VulnerabilityStatusNotAffected, sev1beta1.VulnerabilityStatusFixed:
		return true
	case sev1beta1.VulnerabilityStatusAffected:
		return affectedSuppresses(vuln)
	default:
		return false
	}
}

// affectedSuppresses reports whether an affected entry hides its finding.
//
// The status alone never does. affected asserts that the vulnerability is real and applies,
// which is the opposite of an assertion an author would expect to hide a finding, so two
// further things are required.
//
// First an actionStatement. OpenVEX requires one for every affected statement ("a VEX
// statement MUST include a statement that SHOULD describe actions to remediate or mitigate
// the vulnerability"), so an entry without one is not a valid affected statement and does not
// get to suppress.
//
// Then a response saying the finding will not be remediated. can_not_fix and will_not_fix
// both mean no fix is coming, so the risk has been accepted rather than scheduled. update,
// rollback and workaround_available mean a remediation is planned or already in place, and
// the finding stays visible until it is confirmed. Every stated response has to be a
// non-remediating one: an entry pairing will_not_fix with update is still tracking work, and
// keeping the finding visible is the fail-closed reading of that combination.
func affectedSuppresses(vuln sev1beta1.VulnerabilityException) bool {
	if strings.TrimSpace(vuln.ActionStatement) == "" || len(vuln.Response) == 0 {
		return false
	}
	for _, response := range vuln.Response {
		if !isNonRemediatingResponse(response) {
			return false
		}
	}
	return true
}

func isNonRemediatingResponse(response sev1beta1.VulnerabilityResponse) bool {
	switch response {
	case sev1beta1.VulnerabilityResponseCanNotFix, sev1beta1.VulnerabilityResponseWillNotFix:
		return true
	default:
		return false
	}
}

func buildPolicy(spec sev1beta1.SecurityExceptionSpec, vuln sev1beta1.VulnerabilityException, namespace string, src suppressionSource) armotypes.VulnerabilityExceptionPolicy {
	vulnerabilityPolicies := []armotypes.VulnerabilityPolicy{
		{Name: strings.TrimSpace(vuln.Vulnerability.ID)},
	}
	for _, alias := range vuln.Vulnerability.Aliases {
		if a := strings.TrimSpace(alias); a != "" {
			vulnerabilityPolicies = append(vulnerabilityPolicies, armotypes.VulnerabilityPolicy{Name: a})
		}
	}

	p := armotypes.VulnerabilityExceptionPolicy{
		// PortalBase.Name identifies the CRD object (the "rule") that produced this policy,
		// since SecurityException/ClusterSecurityException have no separate rule/statement
		// ID — the object's own name is the closest thing to one.
		PortalBase:            armotypes.PortalBase{Name: src.name},
		PolicyType:            "vulnerabilityExceptionPolicy",
		Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: vulnerabilityPolicies,
		Reason:                spec.Reason,
	}

	if exp := effectiveExpiresAt(spec, vuln); exp != nil {
		t := exp.Time
		p.ExpirationDate = &t
	}

	if vuln.ExpiredOnFix {
		b := true
		p.ExpiredOnFix = &b
	}

	p.Designatores = buildDesignators(spec.Match.Resources, namespace)
	p.Attributes = buildSuppressionAttributes(spec, vuln, namespace, src)

	return p
}

// buildSuppressionAttributes records suppression provenance that has no dedicated field on
// armotypes.VulnerabilityExceptionPolicy: which kind of exception CRD matched, its scope, and
// the VEX justification/impact statement behind the suppression. This is surfaced here (rather
// than on the filtered manifest's IgnoreRule) because the manifest's IgnoreRule schema is owned
// by github.com/kubescape/storage and has no such fields.
func buildSuppressionAttributes(spec sev1beta1.SecurityExceptionSpec, vuln sev1beta1.VulnerabilityException, namespace string, src suppressionSource) map[string]interface{} {
	attrs := map[string]interface{}{
		"sourceKind": src.kind,
		"ruleId":     suppressionRuleID(src),
	}
	if src.namespace != "" {
		attrs["sourceNamespace"] = src.namespace
	}
	if src.uid != "" {
		attrs["sourceUID"] = string(src.uid)
	}
	if j := strings.TrimSpace(vuln.Justification); j != "" {
		attrs["justification"] = j
	}
	if s := strings.TrimSpace(vuln.ImpactStatement); s != "" {
		attrs["impactStatement"] = s
	}
	if s := strings.TrimSpace(vuln.ActionStatement); s != "" {
		attrs["actionStatement"] = s
	}
	if len(vuln.Response) > 0 {
		responses := make([]string, 0, len(vuln.Response))
		for _, response := range vuln.Response {
			responses = append(responses, string(response))
		}
		attrs["response"] = responses
	}
	if subs := normalizedSubcomponents(vuln.Subcomponents); len(subs) > 0 {
		attrs[attrSubcomponents] = subs
	}
	if t := normalizedTarget(spec.Match.Resources, namespace); t != "" {
		attrs["normalizedTarget"] = t
	}
	return attrs
}

// suppressionRuleID renders a stable, structured identifier for the CRD object that produced a
// suppression, distinct from both its bare name and the human-authored reason: kind/namespace/name
// for a namespaced SecurityException, kind/name for a cluster-scoped one.
func suppressionRuleID(src suppressionSource) string {
	if src.namespace != "" {
		return src.kind + "/" + src.namespace + "/" + src.name
	}
	return src.kind + "/" + src.name
}

// normalizedTarget renders a human-readable identifier for what an exception's match criteria
// targeted, for suppression-provenance reporting.
func normalizedTarget(resources []sev1beta1.ResourceMatch, namespace string) string {
	if len(resources) == 0 {
		if namespace != "" {
			return "namespace/" + namespace
		}
		return "cluster-wide"
	}
	parts := make([]string, 0, len(resources))
	for _, r := range resources {
		target := r.Kind
		if r.Name != "" {
			target += "/" + r.Name
		}
		if namespace != "" {
			target = namespace + "/" + target
		}
		parts = append(parts, target)
	}
	return strings.Join(parts, ",")
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
//
// recorder is optional: when nil, suppression is still logged via logSuppression but no
// K8s Event is emitted, so callers with no EventRecorder configured (e.g. tests, or
// deployments without SecurityException CRD integration enabled) are unaffected.
//
// The returned map counts each suppressed finding once per distinct sourceKind
// ("SecurityException"/"ClusterSecurityException") that suppressed it -- not once per
// suppressing policy, so two policies of the same kind matching one finding (e.g. by ID and
// by alias) still count as a single match. A policy with no sourceKind attribute (e.g. a
// cloud-sourced exception, not a CRD) is not counted, since this return value only feeds
// the CRD-suppression metric.
func ApplySecurityExceptions(doc *v1beta1.GrypeDocument, exceptions domain.CVEExceptions, recorder record.EventRecorder) map[string]int {
	matchedBySource := map[string]int{}
	if doc == nil || len(exceptions) == 0 {
		return matchedBySource
	}

	var remaining []v1beta1.Match
	for _, m := range doc.Matches {
		isFixed, _ := hasKnownFix(m)
		matched := getCVEExceptionMatchCVENameFromList(exceptions, m.Vulnerability.ID, isFixed)
		matched = scopedToSubcomponent(matched, m.Artifact.PURL)
		if len(matched) > 0 && hasIgnoreAction(matched) {
			doc.IgnoredMatches = append(doc.IgnoredMatches, v1beta1.IgnoredMatch{
				Match: m,
				AppliedIgnoreRules: []v1beta1.IgnoreRule{
					{Vulnerability: m.Vulnerability.ID},
				},
			})
			logSuppression(m, matched, recorder)
			matchedKinds := map[string]struct{}{}
			for _, p := range suppressingPolicies(matched) {
				if kind, ok := p.Attributes["sourceKind"].(string); ok && kind != "" {
					matchedKinds[kind] = struct{}{}
				}
			}
			for kind := range matchedKinds {
				matchedBySource[kind]++
			}
		} else {
			remaining = append(remaining, m)
		}
	}
	doc.Matches = remaining
	return matchedBySource
}

// suppressingPolicies filters matched down to the policies that actually cause suppression,
// mirroring the hasIgnoreAction(matched) condition ApplySecurityExceptions uses to decide
// whether to suppress at all. Without this, a non-Ignore policy passed alongside an Ignore one
// would be misreported by logSuppression as a suppression source.
func suppressingPolicies(matched []armotypes.VulnerabilityExceptionPolicy) []armotypes.VulnerabilityExceptionPolicy {
	var out []armotypes.VulnerabilityExceptionPolicy
	for _, p := range matched {
		if hasIgnoreAction([]armotypes.VulnerabilityExceptionPolicy{p}) {
			out = append(out, p)
		}
	}
	return out
}

// logSuppression records why a CVE disappeared from scan results: which exception object
// matched, its scope, and the stated reason/justification. This is logged rather than stored on
// the manifest because the filtered manifest's IgnoreRule (github.com/kubescape/storage) has no
// fields for this provenance; see buildSuppressionAttributes for where it is captured.
//
// When recorder is non-nil, the same suppression is also recorded as a K8s Event on the
// SecurityException/ClusterSecurityException object that caused it, so it shows up in
// `kubectl describe`. The log line is always written regardless of recorder.
func logSuppression(m v1beta1.Match, matched []armotypes.VulnerabilityExceptionPolicy, recorder record.EventRecorder) {
	for _, p := range suppressingPolicies(matched) {
		fields := []helpers.IDetails{
			helpers.String("cve", m.Vulnerability.ID),
			helpers.String("package", m.Artifact.Name),
		}
		if p.Name != "" {
			fields = append(fields, helpers.String("sourceName", p.Name))
		}
		if p.Reason != "" {
			fields = append(fields, helpers.String("reason", p.Reason))
		}
		if kind, ok := p.Attributes["sourceKind"].(string); ok && kind != "" {
			fields = append(fields, helpers.String("sourceKind", kind))
		}
		if ruleID, ok := p.Attributes["ruleId"].(string); ok && ruleID != "" {
			fields = append(fields, helpers.String("ruleId", ruleID))
		}
		if ns, ok := p.Attributes["sourceNamespace"].(string); ok && ns != "" {
			fields = append(fields, helpers.String("sourceNamespace", ns))
		}
		if just, ok := p.Attributes["justification"].(string); ok && just != "" {
			fields = append(fields, helpers.String("justification", just))
		}
		if impact, ok := p.Attributes["impactStatement"].(string); ok && impact != "" {
			fields = append(fields, helpers.String("impactStatement", impact))
		}
		if target, ok := p.Attributes["normalizedTarget"].(string); ok && target != "" {
			fields = append(fields, helpers.String("normalizedTarget", target))
		}
		logger.L().Info("CVE suppressed by security exception", fields...)

		emitSuppressionEvent(recorder, p, m)
	}
}

// emitSuppressionEvent records a K8s Event on the CRD object that produced p, if recorder is
// configured and p carries enough provenance (kind, name, UID) to build an ObjectReference.
// A manually-built *corev1.ObjectReference bypasses live Get and scheme registration entirely
// (client-go/tools/reference.GetReference short-circuits on it), so no K8s client access beyond
// the recorder itself is needed here.
func emitSuppressionEvent(recorder record.EventRecorder, p armotypes.VulnerabilityExceptionPolicy, m v1beta1.Match) {
	if recorder == nil {
		return
	}
	kind, _ := p.Attributes["sourceKind"].(string)
	uid, _ := p.Attributes["sourceUID"].(string)
	if kind == "" || p.Name == "" || uid == "" {
		return
	}
	namespace, _ := p.Attributes["sourceNamespace"].(string)

	ref := &corev1.ObjectReference{
		Kind:       kind,
		APIVersion: securityExceptionAPIVersion,
		Name:       p.Name,
		Namespace:  namespace,
		UID:        types.UID(uid),
	}
	recorder.Eventf(ref, corev1.EventTypeNormal, "VulnerabilitySuppressed",
		"Suppressed %s in package %s", m.Vulnerability.ID, m.Artifact.Name)
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
// alone, because an ExpiredOnFix policy suppresses only the matches of a CVE that have no known
// fix (hasKnownFix, via getCVEExceptionMatchCVENameFromList), so two matches of the same CVE can
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
