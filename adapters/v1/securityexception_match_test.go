package v1

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMatchImages(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		image    string
		want     bool
	}{
		{name: "no patterns matches everything", patterns: nil, image: "docker.io/library/nginx:1.25", want: true},
		{name: "non-empty patterns never match empty image", patterns: []string{"docker.io/library/nginx:*"}, image: "", want: false},
		{name: "tag wildcard matches", patterns: []string{"docker.io/library/nginx:*"}, image: "docker.io/library/nginx:1.25", want: true},
		{name: "tag wildcard matches digest suffix", patterns: []string{"docker.io/library/nginx:*"}, image: "docker.io/library/nginx:latest@sha256:abc", want: true},
		{name: "repo wildcard matches", patterns: []string{"docker.io/*/nginx:*"}, image: "docker.io/library/nginx:1.25", want: true},
		{name: "name wildcard matches", patterns: []string{"docker.io/library/*:*"}, image: "docker.io/library/nginx:1.25", want: true},
		{name: "star does not cross slash", patterns: []string{"*/nginx:*"}, image: "docker.io/library/nginx:1.25", want: false},
		{name: "exact non-match", patterns: []string{"docker.io/library/redis:6"}, image: "docker.io/library/nginx:1.25", want: false},
		{name: "exact match", patterns: []string{"docker.io/library/nginx:1.25"}, image: "docker.io/library/nginx:1.25", want: true},
		{name: "OR across patterns", patterns: []string{"docker.io/library/redis:*", "docker.io/library/nginx:*"}, image: "docker.io/library/nginx:1.25", want: true},
		{name: "malformed pattern is skipped", patterns: []string{"[bad"}, image: "docker.io/library/nginx:1.25", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchImages(tt.patterns, tt.image))
		})
	}
}

func TestMatchResources(t *testing.T) {
	target := ExceptionTarget{Kind: "deployment", Name: "nginx", APIGroup: "apps"}
	tests := []struct {
		name      string
		resources []sev1beta1.ResourceMatch
		target    ExceptionTarget
		want      bool
	}{
		{name: "empty matches everything", resources: nil, target: target, want: true},
		{name: "kind case-insensitive match", resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", Name: "nginx"}}, target: target, want: true},
		{name: "kind-only match ignores name", resources: []sev1beta1.ResourceMatch{{Kind: "Deployment"}}, target: target, want: true},
		{name: "kind mismatch", resources: []sev1beta1.ResourceMatch{{Kind: "StatefulSet"}}, target: target, want: false},
		{name: "name mismatch", resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", Name: "other"}}, target: target, want: false},
		{name: "OR across entries", resources: []sev1beta1.ResourceMatch{{Kind: "StatefulSet", Name: "db"}, {Kind: "Deployment", Name: "nginx"}}, target: target, want: true},
		{name: "apiGroup match", resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", APIGroup: "apps"}}, target: target, want: true},
		{name: "apiGroup mismatch", resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", APIGroup: "batch"}}, target: target, want: false},
		{name: "apiGroup skipped when target group unknown", resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", APIGroup: "apps"}}, target: ExceptionTarget{Kind: "deployment", Name: "nginx"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchResources(tt.resources, tt.target))
		})
	}
}

func TestLabelSelectorMatches(t *testing.T) {
	tests := []struct {
		name     string
		selector *metav1.LabelSelector
		labels   map[string]string
		want     bool
	}{
		{name: "nil selector matches everything", selector: nil, labels: map[string]string{"app": "nginx"}, want: true},
		{name: "empty selector matches everything", selector: &metav1.LabelSelector{}, labels: map[string]string{"app": "nginx"}, want: true},
		{name: "matchLabels match", selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}, labels: map[string]string{"app": "nginx", "env": "prod"}, want: true},
		{name: "matchLabels mismatch", selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}, labels: map[string]string{"app": "redis"}, want: false},
		{name: "matchLabels against nil labels", selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}, labels: nil, want: false},
		{
			name: "matchExpressions In match",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod", "staging"}},
			}},
			labels: map[string]string{"env": "staging"},
			want:   true,
		},
		{
			name: "matchExpressions In mismatch",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
			}},
			labels: map[string]string{"env": "dev"},
			want:   false,
		},
		{
			name: "invalid selector fails closed",
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: nil}, // In requires values
			}},
			labels: map[string]string{"env": "prod"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, labelSelectorMatches(tt.selector, tt.labels))
		})
	}
}

func TestMatchExceptionTarget(t *testing.T) {
	target := ExceptionTarget{
		Namespace:       "production",
		Kind:            "deployment",
		Name:            "nginx",
		Image:           "docker.io/library/nginx:1.25",
		WorkloadLabels:  map[string]string{"app": "nginx"},
		NamespaceLabels: map[string]string{"env": "staging"},
	}

	t.Run("empty match applies to all", func(t *testing.T) {
		assert.True(t, matchExceptionTarget(sev1beta1.ExceptionMatch{}, target, false))
		assert.True(t, matchExceptionTarget(sev1beta1.ExceptionMatch{}, target, true))
	})

	t.Run("images gate the match", func(t *testing.T) {
		assert.True(t, matchExceptionTarget(sev1beta1.ExceptionMatch{Images: []string{"docker.io/library/nginx:*"}}, target, true))
		assert.False(t, matchExceptionTarget(sev1beta1.ExceptionMatch{Images: []string{"docker.io/library/redis:*"}}, target, true))
	})

	t.Run("resources gate the match", func(t *testing.T) {
		assert.True(t, matchExceptionTarget(sev1beta1.ExceptionMatch{Resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", Name: "nginx"}}}, target, false))
		assert.False(t, matchExceptionTarget(sev1beta1.ExceptionMatch{Resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", Name: "other"}}}, target, false))
	})

	t.Run("objectSelector gates the match", func(t *testing.T) {
		assert.True(t, matchExceptionTarget(sev1beta1.ExceptionMatch{ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}}, target, false))
		assert.False(t, matchExceptionTarget(sev1beta1.ExceptionMatch{ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis"}}}, target, false))
	})

	t.Run("all specified selectors must match (AND)", func(t *testing.T) {
		m := sev1beta1.ExceptionMatch{
			Resources: []sev1beta1.ResourceMatch{{Kind: "Deployment", Name: "nginx"}},
			Images:    []string{"docker.io/library/redis:*"}, // does not match
		}
		assert.False(t, matchExceptionTarget(m, target, true))
	})

	t.Run("namespaceSelector only applies to cluster-scoped", func(t *testing.T) {
		m := sev1beta1.ExceptionMatch{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}}
		// cluster-scoped: namespace labels are env=staging, so selector env=prod does not match
		assert.False(t, matchExceptionTarget(m, target, true))
		// namespaced: namespaceSelector is ignored -> matches
		assert.True(t, matchExceptionTarget(m, target, false))
	})

	t.Run("namespaceSelector cluster-scoped positive", func(t *testing.T) {
		m := sev1beta1.ExceptionMatch{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "staging"}}}
		assert.True(t, matchExceptionTarget(m, target, true))
	})
}

func TestConvertScopesByMatch(t *testing.T) {
	cveEntry := []sev1beta1.VulnerabilityException{{Vulnerability: sev1beta1.VulnerabilityRef{ID: "CVE-2023-1"}}}

	t.Run("CSE images scope filters by image", func(t *testing.T) {
		cse := []sev1beta1.ClusterSecurityException{{
			Spec: sev1beta1.SecurityExceptionSpec{
				Match:           sev1beta1.ExceptionMatch{Images: []string{"docker.io/library/nginx:*"}},
				Vulnerabilities: cveEntry,
			},
		}}
		matching := ConvertToVulnerabilityExceptionPolicies(nil, cse, ExceptionTarget{Image: "docker.io/library/nginx:1.25"})
		assert.Len(t, matching, 1)
		notMatching := ConvertToVulnerabilityExceptionPolicies(nil, cse, ExceptionTarget{Image: "docker.io/library/redis:7"})
		assert.Empty(t, notMatching)
	})

	t.Run("SE objectSelector scope filters by workload labels", func(t *testing.T) {
		se := []sev1beta1.SecurityException{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "production"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Match:           sev1beta1.ExceptionMatch{ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}},
				Vulnerabilities: cveEntry,
			},
		}}
		matching := ConvertToVulnerabilityExceptionPolicies(se, nil, ExceptionTarget{Namespace: "production", WorkloadLabels: map[string]string{"app": "nginx"}})
		assert.Len(t, matching, 1)
		notMatching := ConvertToVulnerabilityExceptionPolicies(se, nil, ExceptionTarget{Namespace: "production", WorkloadLabels: map[string]string{"app": "redis"}})
		assert.Empty(t, notMatching)
	})

	t.Run("CSE namespaceSelector scope filters by namespace labels", func(t *testing.T) {
		cse := []sev1beta1.ClusterSecurityException{{
			Spec: sev1beta1.SecurityExceptionSpec{
				Match:           sev1beta1.ExceptionMatch{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "staging"}}},
				Vulnerabilities: cveEntry,
			},
		}}
		matching := ConvertToVulnerabilityExceptionPolicies(nil, cse, ExceptionTarget{NamespaceLabels: map[string]string{"env": "staging"}})
		assert.Len(t, matching, 1)
		notMatching := ConvertToVulnerabilityExceptionPolicies(nil, cse, ExceptionTarget{NamespaceLabels: map[string]string{"env": "prod"}})
		assert.Empty(t, notMatching)
	})

	t.Run("namespaced SE ignores namespaceSelector", func(t *testing.T) {
		se := []sev1beta1.SecurityException{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "production"},
			Spec: sev1beta1.SecurityExceptionSpec{
				Match:           sev1beta1.ExceptionMatch{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}},
				Vulnerabilities: cveEntry,
			},
		}}
		// even though namespace labels don't match, a namespaced SE is applied
		policies := ConvertToVulnerabilityExceptionPolicies(se, nil, ExceptionTarget{Namespace: "production", NamespaceLabels: map[string]string{"env": "staging"}})
		assert.Len(t, policies, 1)
	})
}

func TestBuildExceptionTarget(t *testing.T) {
	workload := domain.ScanCommand{
		Wlid:               "wlid://cluster-c/namespace-production/deployment-nginx",
		ImageTagNormalized: "docker.io/library/nginx:1.25",
	}

	t.Run("parses wlid and image, no labels when no selectors", func(t *testing.T) {
		repo := &mockSecurityExceptionRepo{
			workloadLabels:  map[string]string{"app": "nginx"},
			namespaceLabels: map[string]string{"env": "staging"},
		}
		se := []sev1beta1.SecurityException{{Spec: sev1beta1.SecurityExceptionSpec{Match: sev1beta1.ExceptionMatch{Resources: []sev1beta1.ResourceMatch{{Kind: "Deployment"}}}}}}
		target := BuildExceptionTarget(context.Background(), workload, se, nil, repo)
		assert.Equal(t, "production", target.Namespace)
		assert.Equal(t, "nginx", target.Name)
		assert.Equal(t, "docker.io/library/nginx:1.25", target.Image)
		// no objectSelector/namespaceSelector => labels not resolved
		assert.Nil(t, target.WorkloadLabels)
		assert.Nil(t, target.NamespaceLabels)
	})

	t.Run("resolves workload labels when objectSelector present", func(t *testing.T) {
		repo := &mockSecurityExceptionRepo{workloadLabels: map[string]string{"app": "nginx"}}
		se := []sev1beta1.SecurityException{{Spec: sev1beta1.SecurityExceptionSpec{Match: sev1beta1.ExceptionMatch{ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}}}}}
		target := BuildExceptionTarget(context.Background(), workload, se, nil, repo)
		assert.Equal(t, map[string]string{"app": "nginx"}, target.WorkloadLabels)
	})

	t.Run("resolves namespace labels when CSE namespaceSelector present", func(t *testing.T) {
		repo := &mockSecurityExceptionRepo{namespaceLabels: map[string]string{"env": "staging"}}
		cse := []sev1beta1.ClusterSecurityException{{Spec: sev1beta1.SecurityExceptionSpec{Match: sev1beta1.ExceptionMatch{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "staging"}}}}}}
		target := BuildExceptionTarget(context.Background(), workload, nil, cse, repo)
		assert.Equal(t, map[string]string{"env": "staging"}, target.NamespaceLabels)
		assert.Nil(t, target.WorkloadLabels)
	})

	t.Run("nil repo yields no labels", func(t *testing.T) {
		target := BuildExceptionTarget(context.Background(), workload, nil, nil, nil)
		assert.Equal(t, "docker.io/library/nginx:1.25", target.Image)
		assert.Nil(t, target.WorkloadLabels)
	})
}
