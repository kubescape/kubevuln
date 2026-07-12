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
	APIGroup  string
	// Image is the fully-qualified, normalized image reference (as produced by
	// tools.NormalizeReference), e.g. "docker.io/library/nginx:latest".
	Image string
	// WorkloadLabels are the labels of the workload being scanned, resolved
	// lazily and only when an exception uses match.objectSelector.
	WorkloadLabels map[string]string
	// NamespaceLabels are the labels of the workload's namespace, resolved
	// lazily and only when a ClusterSecurityException uses match.namespaceSelector.
	NamespaceLabels map[string]string
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
	if !labelSelectorMatches(match.ObjectSelector, target.WorkloadLabels) {
		return false
	}
	if clusterScoped && !labelSelectorMatches(match.NamespaceSelector, target.NamespaceLabels) {
		return false
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
		if r.Kind != "" && !strings.EqualFold(r.Kind, target.Kind) {
			continue
		}
		if r.Name != "" && r.Name != target.Name {
			continue
		}
		// apiGroup is optional and defaults to all groups. Only enforce it when
		// both the exception and the resolved target group are known.
		if r.APIGroup != "" && target.APIGroup != "" && !strings.EqualFold(r.APIGroup, target.APIGroup) {
			continue
		}
		return true
	}
	return false
}

// matchImages returns true if the image matches any of the glob patterns (OR).
// Patterns use path.Match syntax ('*' does not cross '/'). An empty list
// matches everything; a non-empty list never matches an empty image.
func matchImages(patterns []string, image string) bool {
	if len(patterns) == 0 {
		return true
	}
	if image == "" {
		return false
	}
	for _, p := range patterns {
		if ok, err := path.Match(p, image); err == nil && ok {
			return true
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
			target.APIGroup = gvr.Group
		}
	}

	if repo == nil {
		return target
	}

	if usesObjectSelector(exceptions, clusterExceptions) && namespace != "" && kind != "" && name != "" {
		if lbls, err := repo.GetWorkloadLabels(ctx, namespace, kind, name); err != nil {
			logger.L().Ctx(ctx).Warning("failed to resolve workload labels for SecurityException objectSelector",
				helpers.Error(err), helpers.String("namespace", namespace), helpers.String("kind", kind), helpers.String("name", name))
		} else {
			target.WorkloadLabels = lbls
		}
	}

	if usesNamespaceSelector(clusterExceptions) && namespace != "" {
		if lbls, err := repo.GetNamespaceLabels(ctx, namespace); err != nil {
			logger.L().Ctx(ctx).Warning("failed to resolve namespace labels for ClusterSecurityException namespaceSelector",
				helpers.Error(err), helpers.String("namespace", namespace))
		} else {
			target.NamespaceLabels = lbls
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
