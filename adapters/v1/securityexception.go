package v1

import (
	"context"
	"encoding/json"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	sev1 "github.com/kubescape/kubevuln/pkg/securityexception/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	securityExceptionGVR = schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1",
		Resource: "securityexceptions",
	}
	clusterSecurityExceptionGVR = schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1",
		Resource: "clustersecurityexceptions",
	}
)

// SecurityExceptionAdapter fetches SecurityException and ClusterSecurityException
// CRDs from the cluster via the dynamic client.
type SecurityExceptionAdapter struct {
	client dynamic.Interface
}

// NewSecurityExceptionAdapter creates a new SecurityExceptionAdapter.
func NewSecurityExceptionAdapter(client dynamic.Interface) *SecurityExceptionAdapter {
	return &SecurityExceptionAdapter{client: client}
}

// GetSecurityExceptions lists namespaced SecurityExceptions and cluster-scoped
// ClusterSecurityExceptions. It returns both lists so callers can convert them.
func (a *SecurityExceptionAdapter) GetSecurityExceptions(ctx context.Context, namespace string) ([]sev1.SecurityException, []sev1.ClusterSecurityException, error) {
	// List namespaced SecurityExceptions
	seUnstructured, err := a.client.Resource(securityExceptionGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	raw, err := json.Marshal(seUnstructured)
	if err != nil {
		return nil, nil, err
	}
	var seList sev1.SecurityExceptionList
	if err := json.Unmarshal(raw, &seList); err != nil {
		return nil, nil, err
	}

	// List cluster-scoped ClusterSecurityExceptions
	cseUnstructured, err := a.client.Resource(clusterSecurityExceptionGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	raw, err = json.Marshal(cseUnstructured)
	if err != nil {
		return nil, nil, err
	}
	var cseList sev1.ClusterSecurityExceptionList
	if err := json.Unmarshal(raw, &cseList); err != nil {
		return nil, nil, err
	}

	return seList.Items, cseList.Items, nil
}

// convertToVulnerabilityExceptionPolicies converts SecurityException and
// ClusterSecurityException CRDs into armotypes.VulnerabilityExceptionPolicy
// slices compatible with the existing exception pipeline.
func convertToVulnerabilityExceptionPolicies(exceptions []sev1.SecurityException, clusterExceptions []sev1.ClusterSecurityException) []armotypes.VulnerabilityExceptionPolicy {
	var policies []armotypes.VulnerabilityExceptionPolicy

	now := time.Now()

	for i := range exceptions {
		se := &exceptions[i]
		if isExpired(se.Spec.ExpiresAt, now) {
			continue
		}
		namespace := se.Namespace
		for _, vuln := range se.Spec.Vulnerabilities {
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
			p := buildPolicy(cse.Spec, vuln, "")
			policies = append(policies, p)
		}
	}

	return policies
}

func isExpired(expiresAt *metav1.Time, now time.Time) bool {
	return expiresAt != nil && expiresAt.Time.Before(now)
}

func buildPolicy(spec sev1.SecurityExceptionSpec, vuln sev1.VulnerabilityException, namespace string) armotypes.VulnerabilityExceptionPolicy {
	p := armotypes.VulnerabilityExceptionPolicy{
		PolicyType: "vulnerabilityExceptionPolicy",
		Actions:    []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
		VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
			{Name: vuln.Vulnerability.ID},
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

func buildDesignators(resources []sev1.ResourceMatch, namespace string) []identifiers.PortalDesignator {
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
		designators = append(designators, identifiers.PortalDesignator{
			DesignatorType: identifiers.DesignatorAttributes,
			Attributes:     attrs,
		})
	}
	return designators
}
