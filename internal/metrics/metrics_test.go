package metrics

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
)

func TestNewAndHandler(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	require.NotNil(t, m)

	m.ScanCounter.Add(context.Background(), 1, metric.WithAttributes())
	m.ScanDuration.Record(context.Background(), 0.5, metric.WithAttributes())
	m.RejectCounter.Add(context.Background(), 1, metric.WithAttributes())
	m.ExceptionsDegradedCounter.Add(context.Background(), 1, metric.WithAttributes())
	RecordScanFallback(context.Background(), ComponentInProcess, FallbackCategoryRegistryAuth, FallbackStrategyAnonymous, FallbackOutcomeSucceeded)
	RecordSourceResolution(context.Background(), ComponentInProcess, true, true)
	RecordRegistryAuthCache(context.Background(), FallbackStrategyECR, RegistryAuthCacheHit)
	RecordTempDirSweep(context.Background(), ComponentInProcess, 3)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, "kubevuln_scans_completed_total"), body)
	assert.True(t, strings.Contains(body, "kubevuln_scan_duration_seconds"), body)
	assert.True(t, strings.Contains(body, "kubevuln_scan_rejections_total"), body)
	assert.True(t, strings.Contains(body, "kubevuln_exceptions_degraded_total"), body)
	assert.True(t, strings.Contains(body, `kubevuln_scan_fallbacks_total{category="registry_auth",component="in_process",outcome="succeeded",strategy="anonymous"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_scan_source_resolution_total{component="in_process",outcome="fallback_assisted_success"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_registry_auth_cache_total{result="hit",strategy="ecr"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_temp_dir_sweep_removed_total{component="in_process"} 3`), body)
}

func TestRecordTempDirSweep_ZeroOrNegativeRemovedIsANoOp(t *testing.T) {
	m, err := New()
	require.NoError(t, err)

	// A sweep that removed nothing is the steady-state, common case; asserting it emits no
	// series keeps the metric's presence itself meaningful (any series at all means the sweep
	// has reclaimed something at least once), and avoids emitting a zero-valued series on
	// every tick, forever, from both cmd/http and cmd/sbom-scanner.
	RecordTempDirSweep(context.Background(), ComponentInProcess, 0)
	RecordTempDirSweep(context.Background(), ComponentInProcess, -1)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)

	assert.False(t, strings.Contains(w.Body.String(), "kubevuln_temp_dir_sweep_removed_total"), w.Body.String())
}

func TestRecordTempDirSweep_BeforeNewIsANoOp(t *testing.T) {
	// Mirrors the existing package-level-var pattern (RecordScanFallback et al.): the sidecar
	// binary (cmd/sbom-scanner) never calls metrics.New(), so RecordTempDirSweep must not panic
	// when called against a nil counter.
	recorderMu.Lock()
	previous := tempDirSweepCounter
	tempDirSweepCounter = nil
	recorderMu.Unlock()
	defer func() {
		recorderMu.Lock()
		tempDirSweepCounter = previous
		recorderMu.Unlock()
	}()

	assert.NotPanics(t, func() {
		RecordTempDirSweep(context.Background(), ComponentSidecar, 5)
	})
}

func TestMeterRegistersObservableGauge(t *testing.T) {
	m, err := New()
	require.NoError(t, err)

	_, err = m.Meter().Int64ObservableGauge(
		"kubevuln_test_gauge_local",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(42)
			return nil
		}),
	)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)

	assert.True(t, strings.Contains(w.Body.String(), "kubevuln_test_gauge_local"), w.Body.String())
}
