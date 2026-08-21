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

// scrape renders the current metric state the way the /metrics endpoint would, so the
// assertions below read the exposition text an operator actually sees rather than the
// SDK's internal state.
func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	require.Equal(t, 200, w.Code)
	return w.Body.String()
}

// TestRecordSingleflightHit covers the counter that says how often a duplicate SBOM
// request was served by an in-flight one rather than pulling the image again. It is the
// only evidence singleflight is doing anything, so the target label has to be right:
// without it the series cannot be attributed to a stage.
func TestRecordSingleflightHit(t *testing.T) {
	m, err := New()
	require.NoError(t, err)

	// "sbom_generation" is the only target used in production today
	// (ScanService.getOrCreateSBOM), so it is the one worth pinning.
	RecordSingleflightHit(context.Background(), "sbom_generation")
	RecordSingleflightHit(context.Background(), "sbom_generation")
	RecordSingleflightHit(context.Background(), "other_target")

	body := scrape(t, m)
	assert.Contains(t, body, `kubevuln_singleflight_hits_total{target="sbom_generation"} 2`, body)
	assert.Contains(t, body, `kubevuln_singleflight_hits_total{target="other_target"} 1`, body)
}

// TestRecordRetryAttempt covers all three outcomes RetryWithBackoff can report. They are
// distinct signals and only useful if they stay distinct: "attempt" says the operation is
// under rate-limit pressure, "success" says backing off resolved it, and "exhausted" says
// it did not and the scan failed.
func TestRecordRetryAttempt(t *testing.T) {
	m, err := New()
	require.NoError(t, err)

	ctx := context.Background()
	RecordRetryAttempt(ctx, "sbom_generation", RetryOutcomeAttempt)
	RecordRetryAttempt(ctx, "sbom_generation", RetryOutcomeAttempt)
	RecordRetryAttempt(ctx, "sbom_generation", RetryOutcomeSuccess)
	RecordRetryAttempt(ctx, "sbom_generation", RetryOutcomeExhausted)

	body := scrape(t, m)
	assert.Contains(t, body, `kubevuln_retry_attempts_total{operation="sbom_generation",outcome="attempt"} 2`, body)
	assert.Contains(t, body, `kubevuln_retry_attempts_total{operation="sbom_generation",outcome="success"} 1`, body)
	assert.Contains(t, body, `kubevuln_retry_attempts_total{operation="sbom_generation",outcome="exhausted"} 1`, body)
}

// TestRecordSourceResolution_AllOutcomes covers the (usedFallback, success) to outcome
// mapping. Only fallback_assisted_success was previously exercised, leaving the other
// three arms of the switch free to be wrong.
//
// The two that matter most are the ones that look similar and mean opposite things:
// fallback_assisted_success is the auth ladder working as designed, first_pass_failure is
// a resolution that failed without a fallback ever being tried.
func TestRecordSourceResolution_AllOutcomes(t *testing.T) {
	tests := []struct {
		name         string
		usedFallback bool
		success      bool
		want         string
	}{
		{"first pass succeeded", false, true, SourceResolutionFirstPassSuccess},
		{"fallback rescued it", true, true, SourceResolutionFallbackAssistedSuccess},
		{"fallback tried and failed", true, false, SourceResolutionFallbackFailed},
		{"failed before any fallback", false, false, SourceResolutionFirstPassFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := New()
			require.NoError(t, err)

			RecordSourceResolution(context.Background(), ComponentSidecar, tt.usedFallback, tt.success)

			body := scrape(t, m)
			assert.Contains(t, body,
				`kubevuln_scan_source_resolution_total{component="sidecar",outcome="`+tt.want+`"} 1`, body)
		})
	}
}

// TestRecordSourceResolution_OutcomesAreDistinct guards the mapping as a whole rather than
// one arm at a time: four different inputs must produce four different labels, so a switch
// arm cannot be collapsed into another without failing here.
func TestRecordSourceResolution_OutcomesAreDistinct(t *testing.T) {
	m, err := New()
	require.NoError(t, err)

	ctx := context.Background()
	RecordSourceResolution(ctx, ComponentInProcess, false, true)
	RecordSourceResolution(ctx, ComponentInProcess, true, true)
	RecordSourceResolution(ctx, ComponentInProcess, true, false)
	RecordSourceResolution(ctx, ComponentInProcess, false, false)

	body := scrape(t, m)
	for _, outcome := range []string{
		SourceResolutionFirstPassSuccess,
		SourceResolutionFallbackAssistedSuccess,
		SourceResolutionFallbackFailed,
		SourceResolutionFirstPassFailure,
	} {
		assert.Contains(t, body,
			`kubevuln_scan_source_resolution_total{component="in_process",outcome="`+outcome+`"} 1`, body)
	}
}

// TestShutdown covers the graceful-shutdown hook cmd/http calls on its way out.
//
// Recording after shutdown is checked too. The package-level counters outlive the provider
// they came from, and a scan goroutine can still be unwinding while shutdown runs, so a
// record on a shut-down provider has to be harmless rather than a panic on the way out.
func TestShutdown(t *testing.T) {
	// New installs the package-level counters, so leave a live provider behind whatever
	// this test does to them; test order must not decide whether later tests can record.
	defer func() {
		_, err := New()
		require.NoError(t, err)
	}()

	m, err := New()
	require.NoError(t, err)
	RecordSingleflightHit(context.Background(), "sbom_generation")
	require.Contains(t, scrape(t, m), "kubevuln_singleflight_hits_total")

	require.NoError(t, m.Shutdown(context.Background()))

	// Shutdown really stopped the reader rather than just returning nil: the exporter now
	// has nothing to collect, so the endpoint still answers 200 but with an empty body.
	assert.Empty(t, scrape(t, m), "reader should be stopped after Shutdown")

	// And the provider saw it. A second Shutdown reports the reader is already down, which
	// a Shutdown that never reached the provider could not do.
	assert.ErrorContains(t, m.Shutdown(context.Background()), "shutdown")

	assert.NotPanics(t, func() {
		RecordSingleflightHit(context.Background(), "sbom_generation")
		RecordRetryAttempt(context.Background(), "sbom_generation", RetryOutcomeAttempt)
		RecordScanFallback(context.Background(), ComponentInProcess,
			FallbackCategoryRegistryAuth, FallbackStrategyAnonymous, FallbackOutcomeFailed)
	})
}

// TestRecordersBeforeNewAreNoOps extends the guarantee TestRecordTempDirSweep_BeforeNewIsANoOp
// makes for one recorder to the rest of them. cmd/sbom-scanner never calls metrics.New, so
// every recorder reachable from the sidecar runs against a nil counter in production.
func TestRecordersBeforeNewAreNoOps(t *testing.T) {
	recorderMu.Lock()
	prevFallback, prevSource := fallbackCounter, sourceResolutionCounter
	prevAuth, prevSingleflight := registryAuthCacheCounter, singleflightHitsCounter
	prevRetry := retryAttemptsCounter
	fallbackCounter, sourceResolutionCounter = nil, nil
	registryAuthCacheCounter, singleflightHitsCounter = nil, nil
	retryAttemptsCounter = nil
	recorderMu.Unlock()
	defer func() {
		recorderMu.Lock()
		fallbackCounter, sourceResolutionCounter = prevFallback, prevSource
		registryAuthCacheCounter, singleflightHitsCounter = prevAuth, prevSingleflight
		retryAttemptsCounter = prevRetry
		recorderMu.Unlock()
	}()

	ctx := context.Background()
	assert.NotPanics(t, func() {
		RecordScanFallback(ctx, ComponentSidecar, FallbackCategoryPlatform,
			FallbackStrategyPlatformMismatch, FallbackOutcomeFailed)
		RecordSourceResolution(ctx, ComponentSidecar, true, false)
		RecordRegistryAuthCache(ctx, FallbackStrategyECR, RegistryAuthCacheMiss)
		RecordSingleflightHit(ctx, "sbom_generation")
		RecordRetryAttempt(ctx, "sbom_generation", RetryOutcomeExhausted)
	})
}
