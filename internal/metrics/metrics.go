package metrics

import (
	"context"
	"net/http"
	"sync"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// scanDurationBuckets are explicit histogram boundaries (in seconds) for
// kubevuln_scan_duration_seconds. The OTel SDK default boundaries are
// millisecond-shaped ([0, 5, 10, 25, ...]) and collapse every scan under 5s into
// a single bucket, which is most of the traffic on this instrument.
var scanDurationBuckets = []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1800}

const (
	ComponentInProcess = "in_process"
	ComponentSidecar   = "sidecar"

	FallbackCategoryRegistryAuth       = "registry_auth"
	FallbackCategoryPlatform           = "platform"
	FallbackCategorySizeClassification = "size_classification"

	FallbackStrategyAnonymous        = "anonymous"
	FallbackStrategyECR              = "ecr"
	FallbackStrategyGCPADC           = "gcp_adc"
	FallbackStrategyImageTooLarge    = "image_too_large"
	FallbackStrategyIncomplete       = "incomplete"
	FallbackStrategyPlatformMismatch = "platform_mismatch"
	FallbackStrategySBOMTooLarge     = "sbom_too_large"

	FallbackOutcomeClassified = "classified"
	FallbackOutcomeFailed     = "failed"
	FallbackOutcomeSucceeded  = "succeeded"

	SourceResolutionFirstPassSuccess        = "first_pass_success"
	SourceResolutionFallbackAssistedSuccess = "fallback_assisted_success"
	SourceResolutionFallbackFailed          = "fallback_failed"
	SourceResolutionFirstPassFailure        = "first_pass_failure"
)

var recorderMu sync.RWMutex
var fallbackCounter metric.Int64Counter
var sourceResolutionCounter metric.Int64Counter

// Metrics wraps the OTel meter and Prometheus exporter used to expose kubevuln's
// operational metrics (worker-pool backlog, scan outcomes, rejection counts) on
// a GET /metrics HTTP route.
type Metrics struct {
	provider *sdkmetric.MeterProvider
	handler  http.Handler

	ScanDuration              metric.Float64Histogram
	ScanCounter               metric.Int64Counter
	RejectCounter             metric.Int64Counter
	ExceptionsDegradedCounter metric.Int64Counter
	ScanFallbackCounter       metric.Int64Counter
	SourceResolutionCounter   metric.Int64Counter
}

// New builds a Metrics instance backed by a Prometheus exporter registered
// with a fresh OTel MeterProvider.
func New() (*Metrics, error) {
	registry := promclient.NewRegistry()
	exporter, err := prometheus.New(
		prometheus.WithRegisterer(registry),
		prometheus.WithoutScopeInfo(),
	)
	if err != nil {
		return nil, err
	}

	res := resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName("kubevuln"))

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithResource(res),
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Name: "kubevuln_scan_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: scanDurationBuckets,
			}},
		)),
	)
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
		"kubevuln_scans_completed_total",
		metric.WithDescription("Total number of scans completed by the HTTP controller, by outcome"),
	)
	if err != nil {
		return nil, err
	}

	rejectCounter, err := meter.Int64Counter(
		"kubevuln_scan_rejections_total",
		metric.WithDescription("Total number of scan requests rejected at validation time, by reason"),
	)
	if err != nil {
		return nil, err
	}

	exceptionsDegradedCounter, err := meter.Int64Counter(
		"kubevuln_exceptions_degraded_total",
		metric.WithDescription("Total number of times CVE exception fetching degraded (partially failed) during a scan"),
	)
	if err != nil {
		return nil, err
	}

	scanFallbackCounter, err := meter.Int64Counter(
		"kubevuln_scan_fallbacks_total",
		metric.WithDescription("Total number of scan fallback strategy changes, by component, category, strategy, and outcome"),
	)
	if err != nil {
		return nil, err
	}

	sourceResolutionMetric, err := meter.Int64Counter(
		"kubevuln_scan_source_resolution_total",
		metric.WithDescription("Total number of source-resolution outcomes, distinguishing first-pass and fallback-assisted scans"),
	)
	if err != nil {
		return nil, err
	}

	recorderMu.Lock()
	fallbackCounter = scanFallbackCounter
	sourceResolutionCounter = sourceResolutionMetric
	recorderMu.Unlock()

	return &Metrics{
		provider:                  provider,
		handler:                   promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
		ScanDuration:              scanDuration,
		ScanCounter:               scanCounter,
		RejectCounter:             rejectCounter,
		ExceptionsDegradedCounter: exceptionsDegradedCounter,
		ScanFallbackCounter:       scanFallbackCounter,
		SourceResolutionCounter:   sourceResolutionMetric,
	}, nil
}

// Shutdown flushes and releases the underlying MeterProvider's resources. It should be
// called alongside the rest of the process's graceful-shutdown sequence.
func (m *Metrics) Shutdown(ctx context.Context) error {
	return m.provider.Shutdown(ctx)
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

func RecordScanFallback(ctx context.Context, component, category, strategy, outcome string) {
	recorderMu.RLock()
	counter := fallbackCounter
	recorderMu.RUnlock()
	if counter == nil {
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("component", component),
		attribute.String("category", category),
		attribute.String("strategy", strategy),
		attribute.String("outcome", outcome),
	))
}

func RecordSourceResolution(ctx context.Context, component string, usedFallback, success bool) {
	recorderMu.RLock()
	counter := sourceResolutionCounter
	recorderMu.RUnlock()
	if counter == nil {
		return
	}
	outcome := SourceResolutionFirstPassFailure
	switch {
	case usedFallback && success:
		outcome = SourceResolutionFallbackAssistedSuccess
	case usedFallback && !success:
		outcome = SourceResolutionFallbackFailed
	case !usedFallback && success:
		outcome = SourceResolutionFirstPassSuccess
	}
	counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("component", component),
		attribute.String("outcome", outcome),
	))
}
