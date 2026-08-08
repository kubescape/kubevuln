package services

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

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

func (degradedPlatform) GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, error) {
	return nil, domain.ErrExceptionsDegraded
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
