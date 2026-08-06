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

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, "kubevuln_scans_completed_total"), body)
	assert.True(t, strings.Contains(body, "kubevuln_scan_duration_seconds"), body)
	assert.True(t, strings.Contains(body, "kubevuln_scan_rejections_total"), body)
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
