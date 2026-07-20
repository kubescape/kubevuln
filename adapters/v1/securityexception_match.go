package v1

import (
	"context"
	"path"
	"strings"

	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
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
// pinning a tag ("docker.io/library/nginx:1.25") must still match a workload
// deployed with a digest ("docker.io/library/nginx:1.25@sha256:..."), and a
// pattern naming the bare repository ("docker.io/library/nginx") matches that
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
		for _, form := range forms {
			if ok, err := path.Match(p, form); err == nil && ok {
				return true
			}
		}
	}
	return false
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
	if usesObjectSelector(exceptions, clusterExceptions) && namespace != "" && kind != "" && name != "" {
		if lbls, err := repo.GetWorkloadLabels(ctx, namespace, kind, name); err != nil {
			logger.L().Ctx(ctx).Warning("failed to resolve workload labels for SecurityException objectSelector; exception will not apply to this workload",
				helpers.Error(err), helpers.String("namespace", namespace), helpers.String("kind", kind), helpers.String("name", name))
		} else {
			target.WorkloadLabels = lbls
			target.WorkloadLabelsResolved = true
		}
	}

	if usesNamespaceSelector(clusterExceptions) && namespace != "" {
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

func usesObjectSelector(exceptions []sev1beta1.SecurityException, clusterExceptions []sev1beta1.ClusterSecurityException) bool {
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

func usesNamespaceSelector(clusterExceptions []sev1beta1.ClusterSecurityException) bool {
	for i := range clusterExceptions {
		if clusterExceptions[i].Spec.Match.NamespaceSelector != nil {
			return true
		}
	}
	return false
}
