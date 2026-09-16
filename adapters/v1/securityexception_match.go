package v1

import (
	"context"
	"path"
	"strings"

	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
	"github.com/distribution/reference"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// ExceptionTarget describes the workload/image currently being scanned. It is
// evaluated against a SecurityException's spec.match to decide whether the
// exception applies to this scan.
type ExceptionTarget struct {
	Namespace string
	Kind      string
	Name      string
	// APIGroup is the target's resolved API group. A nil pointer means the group
	// is unknown (the kind could not be resolved); an empty string "" is the core
	// group. These must stay distinct so a group-scoped exception never matches a
	// core resource or an unverified one.
	APIGroup *string
	// Image is the fully-qualified, normalized image reference (as produced by
	// tools.NormalizeReference), e.g. "docker.io/library/nginx:latest".
	Image string
	// WorkloadLabels are the labels of the workload being scanned, resolved
	// lazily and only when an exception uses match.objectSelector.
	WorkloadLabels map[string]string
	// NamespaceLabels are the labels of the workload's namespace, resolved
	// lazily and only when a ClusterSecurityException uses match.namespaceSelector.
	NamespaceLabels map[string]string
	// WorkloadLabelsResolved reports whether WorkloadLabels reflect a successful
	// lookup. When an objectSelector is in play but resolution failed (missing
	// workload, nil repo, lookup error), this stays false and matching fails
	// closed — a negative selector (DoesNotExist/NotIn) would otherwise match an
	// empty label set and wrongly suppress findings.
	WorkloadLabelsResolved bool
	// NamespaceLabelsResolved is the namespaceSelector equivalent.
	NamespaceLabelsResolved bool
}

// matchExceptionTarget reports whether spec.match applies to the given target.
//
// Semantics (per the SecurityException design doc):
//   - all specified selector types (resources, images, objectSelector,
//     namespaceSelector) must match (AND);
//   - within resources / images the entries are OR-ed;
//   - an omitted/nil selector matches everything;
//   - namespaceSelector is only meaningful on a ClusterSecurityException
//     (clusterScoped=true); on a namespaced SecurityException it is ignored,
//     since the exception is already scoped to its own namespace.
func matchExceptionTarget(match sev1beta1.ExceptionMatch, target ExceptionTarget, clusterScoped bool) bool {
	if !matchResources(match.Resources, target) {
		return false
	}
	if !matchImages(match.Images, target.Image) {
		return false
	}
	// objectSelector: when a selector is set but the workload's labels could not
	// be resolved, fail closed rather than evaluate against an empty label set.
	if match.ObjectSelector != nil {
		if !target.WorkloadLabelsResolved || !labelSelectorMatches(match.ObjectSelector, target.WorkloadLabels) {
			return false
		}
	}
	if clusterScoped && match.NamespaceSelector != nil {
		if !target.NamespaceLabelsResolved || !labelSelectorMatches(match.NamespaceSelector, target.NamespaceLabels) {
			return false
		}
	}
	return true
}

// matchResources returns true if the target matches any of the resource
// entries (OR). An empty list matches everything.
func matchResources(resources []sev1beta1.ResourceMatch, target ExceptionTarget) bool {
	if len(resources) == 0 {
		return true
	}
	for _, r := range resources {
		// An entry that constrains nothing would match every workload, defeating
		// the point of listing resources at all. CRD validation requires kind, but
		// an explicit empty kind still satisfies that, so reject it here too.
		if r.Kind == "" && r.Name == "" && r.APIGroup == "" {
			continue
		}
		if r.Kind != "" && !strings.EqualFold(r.Kind, target.Kind) {
			continue
		}
		if r.Name != "" && r.Name != target.Name {
			continue
		}
		// apiGroup is optional. When the exception pins a group, the target's
		// resolved group must equal it; if the target group is unknown (nil), the
		// exception does not apply — fail closed rather than match a resource whose
		// group was never verified. A non-nil "" is the core group and only matches
		// an exception that pins "" (or none).
		if r.APIGroup != "" && (target.APIGroup == nil || !strings.EqualFold(r.APIGroup, *target.APIGroup)) {
			continue
		}
		return true
	}
	return false
}

// matchImages returns true if the image matches any of the glob patterns (OR).
// Patterns use path.Match syntax ('*' does not cross '/'). An empty list
// matches everything; a non-empty list never matches an empty image.
//
// path.Match is a full-string match, so each pattern is tried against every
// equivalent form of the reference (see tools.ReferenceMatchForms): a pattern
// pinning a tag ("docker.io/library/nginx:1.25" or short "nginx:1.25") must still match a workload
// deployed with a digest ("docker.io/library/nginx:1.25@sha256:..."), and a
// pattern naming the bare repository ("docker.io/library/nginx" or "nginx") matches that
// repository at any tag or digest.
func matchImages(patterns []string, image string) bool {
	if len(patterns) == 0 {
		return true
	}
	if image == "" {
		return false
	}
	forms := tools.ReferenceMatchForms(image)
	for _, p := range patterns {
		pForms := expandPatternForms(p)
		for _, pf := range pForms {
			for _, form := range forms {
				lowerPF := normalizePatternFormForCandidate(pf, form)
				if ok, err := path.Match(lowerPF, form); err == nil && ok {
					return true
				}
			}
		}
	}
	return false
}

// normalizePatternFormForCandidate normalizes the case of registry and repository segments in a pattern
// form to lowercase, while preserving the case of tag and digest portions (which are case-sensitive).
// When form is a bare repository reference (no tag or digest), the pattern is matched as a repository selector
// and all repository text outside character classes is lowercased.
func normalizePatternFormForCandidate(pf, form string) string {
	if pf == "" {
		return ""
	}

	repoPart := pf
	digestPart := ""
	if atIdx := findDigestSeparator(pf); atIdx != -1 {
		repoPart = pf[:atIdx]
		digestPart = pf[atIdx:]
	}

	if tagIdx := findTagSeparator(repoPart); tagIdx != -1 {
		// An explicit ':' unambiguously marks where the tag starts: lowercase only the
		// repository text before it, and leave the tag (case-sensitive) untouched.
		return lowercaseOutsideClasses(repoPart[:tagIdx]) + repoPart[tagIdx:] + digestPart
	}

	// If the candidate form has no tag and no digest, it is a bare repository reference.
	// In that case, the entire pattern is matching repository text, so all repository
	// text outside character classes can be lowercased safely.
	formHasTagOrDigest := findTagSeparator(form) != -1 || findDigestSeparator(form) != -1
	if !formHasTagOrDigest {
		return lowercaseOutsideClasses(repoPart) + digestPart
	}

	// No explicit tag delimiter in pattern, but the candidate form carries a tag/digest.
	// A wildcard may span the hidden tag boundary (e.g. "nginx*RC*" matching "nginx:RC1"),
	// so only the path segment before the last separator is unambiguously repository/registry text.
	lastSlash := findLastPathSeparator(repoPart)
	if lastSlash == -1 {
		return lowercaseOutsideClasses(repoPart) + digestPart
	}
	return lowercaseOutsideClasses(repoPart[:lastSlash+1]) + repoPart[lastSlash+1:] + digestPart
}

func isEscaped(s string, i int) bool {
	count := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		count++
	}
	return count%2 != 0
}

func findDigestSeparator(s string) int {
	inClass := false
	for i := 0; i < len(s); i++ {
		if isEscaped(s, i) {
			continue
		}
		switch s[i] {
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '@':
			if !inClass {
				return i
			}
		}
	}
	return -1
}

func findTagSeparator(s string) int {
	searchStart := 0
	if lastSlash := findLastPathSeparator(s); lastSlash != -1 {
		searchStart = lastSlash + 1
	}
	inClass := false
	for i := searchStart; i < len(s); i++ {
		if isEscaped(s, i) {
			continue
		}
		switch s[i] {
		case '[':
			inClass = true
		case ']':
			inClass = false
		case ':':
			if !inClass {
				return i
			}
		}
	}
	return -1
}

func findLastPathSeparator(s string) int {
	lastSlash := -1
	inClass := false
	for i := 0; i < len(s); i++ {
		if isEscaped(s, i) {
			continue
		}
		switch s[i] {
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				lastSlash = i
			}
		}
	}
	return lastSlash
}

func lowercaseOutsideClasses(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inClass := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isEscaped(s, i) {
			b.WriteByte(c)
			continue
		}
		switch c {
		case '[':
			inClass = true
			b.WriteByte(c)
		case ']':
			inClass = false
			b.WriteByte(c)
		default:
			if inClass {
				b.WriteByte(c)
			} else if c >= 'A' && c <= 'Z' {
				b.WriteByte(c + ('a' - 'A'))
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

func expandPatternForms(p string) []string {
	patterns := []string{p}
	if p == "" {
		return patterns
	}

	if !strings.Contains(p, "/") {
		repoName, _, _ := strings.Cut(p, ":")
		if repoName == "*" {
			return patterns
		}
		patterns = append(patterns, "docker.io/library/"+p)
		return appendNormalizedPattern(patterns, p)
	}

	firstSeg, _, _ := strings.Cut(p, "/")
	hasDomainOrWildcard := strings.ContainsAny(firstSeg, ".:*?") || strings.EqualFold(firstSeg, "localhost")
	if !hasDomainOrWildcard {
		patterns = append(patterns, "docker.io/"+p)
	}

	return appendNormalizedPattern(patterns, p)
}

// appendNormalizedPattern adds p's canonical reference form to patterns, when p is a
// concrete reference rather than a glob.
//
// tools.ReferenceMatchForms normalizes the scanned image but patterns were only ever
// matched literally, so a pattern naming Docker Hub in any spelling other than the
// canonical docker.io/library/... one silently matched nothing: "docker.io/nginx:1.25",
// "index.docker.io/library/nginx:1.25" and "docker.io/nginx" are all valid ways to write
// the official nginx image, and none of them matched it. The expansions above only cover
// patterns with no registry at all, which is the opposite case.
//
// A pattern containing a wildcard is not a parseable reference, so it fails here and keeps
// only the literal forms, leaving glob behaviour untouched. Nothing widens either: the
// canonical form carries the same tag and digest as p and pins the registry p named, so a
// pattern still only matches the registry it asked for (#834). See #863.
func appendNormalizedPattern(patterns []string, p string) []string {
	named, err := reference.ParseNormalizedNamed(p)
	if err != nil {
		return patterns
	}
	canonical := named.String()
	for _, existing := range patterns {
		if existing == canonical {
			return patterns
		}
	}
	return append(patterns, canonical)
}

// labelSelectorMatches evaluates a standard Kubernetes label selector against a
// label set. A nil selector matches everything; an invalid selector matches
// nothing (fail-closed, so a malformed exception never silently suppresses
// findings).
func labelSelectorMatches(sel *metav1.LabelSelector, lbls map[string]string) bool {
	if sel == nil {
		return true
	}
	selector, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return false
	}
	return selector.Matches(labels.Set(lbls))
}

// BuildExceptionTarget assembles the ExceptionTarget for the workload in the
// scan context. Workload and namespace labels are resolved through repo only
// when at least one exception actually uses objectSelector/namespaceSelector,
// to avoid extra API calls on the common path.
func BuildExceptionTarget(ctx context.Context, workload domain.ScanCommand, exceptions []sev1beta1.SecurityException, clusterExceptions []sev1beta1.ClusterSecurityException, repo ports.SecurityExceptionRepository) ExceptionTarget {
	namespace := wlidpkg.GetNamespaceFromWlid(workload.Wlid)
	kind := wlidpkg.GetKindFromWlid(workload.Wlid)
	name := wlidpkg.GetNameFromWlid(workload.Wlid)

	target := ExceptionTarget{
		Namespace: namespace,
		Kind:      kind,
		Name:      name,
		Image:     workload.ImageTagNormalized,
	}

	// Best-effort resolution of the workload's API group for apiGroup matching.
	// If the resource map is not initialized (e.g. offline), apiGroup matching
	// is simply skipped.
	if kind != "" {
		if gvr, err := k8sinterface.GetGroupVersionResource(kind); err == nil {
			group := gvr.Group
			target.APIGroup = &group
		}
	}

	if repo == nil {
		return target
	}

	// Labels are resolved only when a selector actually needs them. A failed
	// resolution leaves the corresponding *Resolved flag false so the selector
	// fails closed in matchExceptionTarget.
	if UsesObjectSelector(exceptions, clusterExceptions) && namespace != "" && kind != "" && name != "" {
		if lbls, err := repo.GetWorkloadLabels(ctx, namespace, kind, name); err != nil {
			logger.L().Ctx(ctx).Warning("failed to resolve workload labels for SecurityException objectSelector; exception will not apply to this workload",
				helpers.Error(err), helpers.String("namespace", namespace), helpers.String("kind", kind), helpers.String("name", name))
		} else {
			target.WorkloadLabels = lbls
			target.WorkloadLabelsResolved = true
		}
	}

	if UsesNamespaceSelector(clusterExceptions) && namespace != "" {
		if lbls, err := repo.GetNamespaceLabels(ctx, namespace); err != nil {
			logger.L().Ctx(ctx).Warning("failed to resolve namespace labels for ClusterSecurityException namespaceSelector; exception will not apply to this namespace",
				helpers.Error(err), helpers.String("namespace", namespace))
		} else {
			target.NamespaceLabels = lbls
			target.NamespaceLabelsResolved = true
		}
	}

	return target
}

// UsesObjectSelector reports whether any of the given exceptions targets workloads by
// objectSelector. Such exceptions fail closed when the workload's labels cannot be
// resolved, making the merged exception set incomplete.
func UsesObjectSelector(exceptions []sev1beta1.SecurityException, clusterExceptions []sev1beta1.ClusterSecurityException) bool {
	for i := range exceptions {
		if exceptions[i].Spec.Match.ObjectSelector != nil {
			return true
		}
	}
	for i := range clusterExceptions {
		if clusterExceptions[i].Spec.Match.ObjectSelector != nil {
			return true
		}
	}
	return false
}

// UsesNamespaceSelector reports whether any of the given cluster exceptions targets
// namespaces by namespaceSelector. Such exceptions fail closed when the namespace's
// labels cannot be resolved, making the merged exception set incomplete.
func UsesNamespaceSelector(clusterExceptions []sev1beta1.ClusterSecurityException) bool {
	for i := range clusterExceptions {
		if clusterExceptions[i].Spec.Match.NamespaceSelector != nil {
			return true
		}
	}
	return false
}
