package services

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// degradedPlatform is a minimal ports.Platform stub whose GetCVEExceptions
// always reports the exception set as degraded.
type degradedPlatform struct{}

func (degradedPlatform) GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, domain.ExceptionStats, error) {
	return nil, domain.ExceptionStats{}, domain.ErrExceptionsDegraded
}
func (degradedPlatform) ReportError(ctx context.Context, err error) error { return nil }
func (degradedPlatform) ReportScanFailure(ctx context.Context, failureCase scanfailure.ScanFailureCase, reason string, scanErr error) error {
	return nil
}
func (degradedPlatform) SendStatus(ctx context.Context, step int) error { return nil }
func (degradedPlatform) SubmitCVE(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest) error {
	return nil
}

func TestApplyExceptionsToManifest_NilMetricsDoesNotPanic(t *testing.T) {
	s := &ScanService{platform: degradedPlatform{}}

	assert.NotPanics(t, func() {
		_, complete := s.applyExceptionsToManifest(context.Background(), domain.CVEManifest{Content: &v1beta1.GrypeDocument{}})
		assert.False(t, complete)
	})
}

func TestApplyExceptionsToManifest_RecordsDegradedMetric(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)

	s := &ScanService{platform: degradedPlatform{}}
	s.SetMetrics(m)

	_, complete := s.applyExceptionsToManifest(context.Background(), domain.CVEManifest{Content: &v1beta1.GrypeDocument{}})
	assert.False(t, complete)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	body := w.Body.String()

	assert.True(t, strings.Contains(body, "kubevuln_exceptions_degraded_total 1"), body)
}

// exceptionsPlatform is a ports.Platform stub that returns a fixed exception set and
// domain.ExceptionStats, so tests can drive applyExceptionsToManifest's exceptions-pipeline
// metric recording (active/expired/matched, see #548) without a real backend or CRD store.
type exceptionsPlatform struct {
	exceptions domain.CVEExceptions
	stats      domain.ExceptionStats
}

func (p exceptionsPlatform) GetCVEExceptions(context.Context) (domain.CVEExceptions, domain.ExceptionStats, error) {
	return p.exceptions, p.stats, nil
}
func (exceptionsPlatform) ReportError(context.Context, error) error { return nil }
func (exceptionsPlatform) ReportScanFailure(context.Context, scanfailure.ScanFailureCase, string, error) error {
	return nil
}
func (exceptionsPlatform) SendStatus(context.Context, int) error { return nil }
func (exceptionsPlatform) SubmitCVE(context.Context, domain.CVEManifest, domain.CVEManifest) error {
	return nil
}

// TestApplyExceptionsToManifest_RecordsExpiredMetric is a regression test for #548:
// SecurityException/ClusterSecurityException CRDs skipped as expired used to be
// unobservable -- not even logged. GetCVEExceptions's domain.ExceptionStats now carries that
// count out of the CRD-conversion layer, and applyExceptionsToManifest turns it into
// kubevuln_exceptions_expired_total, labeled by sourceKind.
func TestApplyExceptionsToManifest_RecordsExpiredMetric(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)

	s := &ScanService{platform: exceptionsPlatform{
		stats: domain.ExceptionStats{ExpiredBySource: map[string]int{
			"SecurityException":        2,
			"ClusterSecurityException": 1,
		}},
	}}
	s.SetMetrics(m)

	_, complete := s.applyExceptionsToManifest(context.Background(), domain.CVEManifest{Content: &v1beta1.GrypeDocument{}})
	assert.True(t, complete)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	body := w.Body.String()

	assert.True(t, strings.Contains(body, `kubevuln_exceptions_expired_total{sourceKind="SecurityException"} 2`), body)
	assert.True(t, strings.Contains(body, `kubevuln_exceptions_expired_total{sourceKind="ClusterSecurityException"} 1`), body)
}

// TestApplyExceptionsToManifest_RecordsActiveAndMatchedMetrics is a regression test for #548:
// suppressions were only observable via a log line (and, once emitted, a Kubernetes Event) --
// there was no Prometheus signal for how many exceptions are in force or how many findings they
// suppress. kubevuln_exceptions_active now reports len(exceptions) (cloud + CRD, whatever the
// platform resolved) and kubevuln_exceptions_matched_total counts each CVE ApplySecurityExceptions
// actually suppresses, labeled by the suppressing policy's sourceKind.
func TestApplyExceptionsToManifest_RecordsActiveAndMatchedMetrics(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)

	exceptions := domain.CVEExceptions{
		{
			PortalBase:            armotypes.PortalBase{Attributes: map[string]interface{}{"sourceKind": "SecurityException"}},
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-SUPPRESSED"}},
		},
	}
	s := &ScanService{platform: exceptionsPlatform{exceptions: exceptions}}
	s.SetMetrics(m)

	cve := domain.CVEManifest{Content: &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-SUPPRESSED"}}},
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-VISIBLE"}}},
		},
	}}

	filtered, complete := s.applyExceptionsToManifest(context.Background(), cve)
	assert.True(t, complete)
	require.Len(t, filtered.Content.Matches, 1, "CVE-SUPPRESSED should have been moved to IgnoredMatches")
	assert.Equal(t, "CVE-VISIBLE", filtered.Content.Matches[0].Vulnerability.ID)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	body := w.Body.String()

	assert.True(t, strings.Contains(body, "kubevuln_exceptions_active 1"), body)
	assert.True(t, strings.Contains(body, `kubevuln_exceptions_matched_total{sourceKind="SecurityException"} 1`), body)
}

// sequentialExceptionsPlatform returns exceptions[0] on the first GetCVEExceptions call and
// exceptions[1] (and later) on every call after, so a test can drive applyExceptionsToManifest
// through two scans with different exception sets.
type sequentialExceptionsPlatform struct {
	exceptionsPlatform
	calls      int
	exceptions []domain.CVEExceptions
}

func (p *sequentialExceptionsPlatform) GetCVEExceptions(context.Context) (domain.CVEExceptions, domain.ExceptionStats, error) {
	i := p.calls
	if i >= len(p.exceptions) {
		i = len(p.exceptions) - 1
	}
	p.calls++
	return p.exceptions[i], domain.ExceptionStats{}, nil
}

// TestApplyExceptionsToManifest_ActiveGaugeResetsToZero is a regression test: the active
// gauge used to be recorded after the len(exceptions)==0 early return, so a scan with no
// exceptions following one that had exceptions left kubevuln_exceptions_active stuck at its
// last nonzero value instead of resetting -- a real Prometheus gauge misreporting bug, not
// just a missed data point (a counter would eventually recover; a gauge would not).
func TestApplyExceptionsToManifest_ActiveGaugeResetsToZero(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)

	onePolicy := domain.CVEExceptions{
		{
			PortalBase:            armotypes.PortalBase{Attributes: map[string]interface{}{"sourceKind": "SecurityException"}},
			PolicyType:            "vulnerabilityExceptionPolicy",
			Actions:               []armotypes.VulnerabilityExceptionPolicyActions{armotypes.Ignore},
			VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{{Name: "CVE-SUPPRESSED"}},
		},
	}
	s := &ScanService{platform: &sequentialExceptionsPlatform{exceptions: []domain.CVEExceptions{onePolicy, {}}}}
	s.SetMetrics(m)

	cve := domain.CVEManifest{Content: &v1beta1.GrypeDocument{
		Matches: []v1beta1.Match{
			{Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-SUPPRESSED"}}},
		},
	}}

	_, complete := s.applyExceptionsToManifest(context.Background(), cve)
	require.True(t, complete)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	require.True(t, strings.Contains(w.Body.String(), "kubevuln_exceptions_active 1"), w.Body.String())

	// second scan resolves zero exceptions; the gauge must follow it down to zero
	_, complete = s.applyExceptionsToManifest(context.Background(), cve)
	require.True(t, complete)

	req = httptest.NewRequest("GET", "/metrics", nil)
	w = httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, "kubevuln_exceptions_active 0"), body)
	assert.False(t, strings.Contains(body, "kubevuln_exceptions_active 1"), body)
}
