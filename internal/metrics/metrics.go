package metrics

import (
	"net/http"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Metrics wraps the OTel meter and Prometheus exporter used to expose kubevuln's
// operational metrics (worker-pool backlog, scan outcomes, rejection counts) on
// a GET /metrics HTTP route.
type Metrics struct {
	provider *sdkmetric.MeterProvider
	handler  http.Handler

	ScanDuration  metric.Float64Histogram
	ScanCounter   metric.Int64Counter
	RejectCounter metric.Int64Counter
}

// New builds a Metrics instance backed by a Prometheus exporter registered
// with a fresh OTel MeterProvider.
func New() (*Metrics, error) {
	registry := promclient.NewRegistry()
	exporter, err := prometheus.New(prometheus.WithRegisterer(registry))
	if err != nil {
		return nil, err
	}

	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	meter := provider.Meter("kubevuln")

	scanDuration, err := meter.Float64Histogram(
		"kubevuln_scan_duration_seconds",
		metric.WithDescription("Duration of scan requests handled by the HTTP controller, in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	scanCounter, err := meter.Int64Counter(
		"kubevuln_scan_requests_total",
		metric.WithDescription("Total number of scan requests handled by the HTTP controller"),
	)
	if err != nil {
		return nil, err
	}

	rejectCounter, err := meter.Int64Counter(
		"kubevuln_scan_rejections_total",
		metric.WithDescription("Total number of scan requests rejected with ErrTooManyRequests"),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		provider:      provider,
		handler:       promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
		ScanDuration:  scanDuration,
		ScanCounter:   scanCounter,
		RejectCounter: rejectCounter,
	}, nil
}

// Meter exposes the underlying OTel meter, e.g. so callers can register
// observable gauges (like worker-pool queue depth) against it.
func (m *Metrics) Meter() metric.Meter {
	return m.provider.Meter("kubevuln")
}

// Handler returns the http.Handler serving Prometheus exposition-format text.
func (m *Metrics) Handler() http.Handler {
	return m.handler
}
