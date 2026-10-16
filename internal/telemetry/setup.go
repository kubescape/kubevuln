// Package telemetry owns bounded operational telemetry, separate from security events.
package telemetry

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kubescape/go-logger/otelsetup"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

const Scope = "kubevuln/operational"

// ConfigureEndpoint preserves LookupEnv semantics, including explicitly empty values.
// disable is a full operational opt-out, including per-signal and legacy endpoints.
func ConfigureEndpoint(ctx context.Context, discover func(context.Context) (string, error)) error {
	if value, present := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT"); present {
		if strings.EqualFold(strings.TrimSpace(value), "disable") || strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
			for _, key := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_COLLECTOR_SVC", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"} {
				_ = os.Setenv(key, "")
			}
		}
		return nil
	}
	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		_ = os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "disable")
		return ConfigureEndpoint(ctx, discover)
	}
	if legacy, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		return os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", legacy)
	}
	if discover == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	endpoint, err := discover(ctx)
	if err != nil {
		return err
	}
	if endpoint == "" {
		return nil
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	return os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
}

// Defaults are component-specific; explicit SDK environment overrides remain effective.
func Defaults() {
	for key, value := range map[string]string{
		"OTEL_METRIC_EXPORT_INTERVAL": "60000", "OTEL_METRIC_EXPORT_TIMEOUT": "3000",
		"OTEL_TRACES_SAMPLER": "traceidratio", "OTEL_TRACES_SAMPLER_ARG": "0.1",
		"OTEL_EXPORTER_OTLP_COMPRESSION": "gzip", "OTEL_EXPORTER_OTLP_TIMEOUT": "3000",
		"OTEL_BSP_MAX_QUEUE_SIZE": "256", "OTEL_BSP_MAX_EXPORT_BATCH_SIZE": "64", "OTEL_BSP_EXPORT_TIMEOUT": "3000",
		"OTEL_BLRP_MAX_QUEUE_SIZE": "256", "OTEL_BLRP_MAX_EXPORT_BATCH_SIZE": "64", "OTEL_BLRP_EXPORT_TIMEOUT": "3000",
	} {
		if _, ok := os.LookupEnv(key); !ok {
			_ = os.Setenv(key, value)
		}
	}
}

// Init reuses shared authentication/resource/trace/log initialization. The shared
// API cannot accept extra metric readers/views, so metrics remain owned by the
// existing component provider with Prometheus and OTLP readers. Startup is serial;
// all environment changes are restored before instruments or workers are built.
func Init(ctx context.Context, cfg otelsetup.ProviderConfig) (func(context.Context) error, error) {
	Defaults()
	keys := []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_COLLECTOR_SVC", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "KS_LOGGER_LEVEL"}
	type env struct {
		value   string
		present bool
	}
	saved := map[string]env{}
	for _, key := range keys {
		v, p := os.LookupEnv(key)
		saved[key] = env{v, p}
	}
	defer func() {
		for key, e := range saved {
			if e.present {
				_ = os.Setenv(key, e.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}()
	base := saved[keys[0]].value
	for _, key := range keys[3:5] {
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, base)
		}
	}
	for _, key := range keys[:3] {
		_ = os.Setenv(key, "")
	}
	// Disable the shared replay listener: it bypasses the export gate and can
	// resend records without a rate bound. Restore the local logger level below.
	_ = os.Setenv("KS_LOGGER_LEVEL", "info")
	shutdown, err := otelsetup.InitProviders(ctx, cfg)
	if err != nil {
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
		otel.SetLoggerProvider(noop.NewLoggerProvider())
		return func(context.Context) error { return nil }, err
	}
	// Only the reviewed operational scope may export. Existing application records
	// retain their local logger behavior but cannot export arbitrary payloads/errors.
	otel.SetLoggerProvider(&safeLogs{LoggerProvider: otel.GetLoggerProvider()})
	otel.SetTracerProvider(&safeTraces{TracerProvider: otel.GetTracerProvider()})
	return shutdown, nil
}

type safeLogs struct{ log.LoggerProvider }

func (p *safeLogs) Logger(name string, opts ...log.LoggerOption) log.Logger {
	if name != Scope {
		return noop.NewLoggerProvider().Logger(name)
	}
	return safeLogger{Logger: p.LoggerProvider.Logger(name, opts...)}
}

type safeTraces struct{ trace.TracerProvider }

func (p *safeTraces) Tracer(name string, opts ...trace.TracerOption) trace.Tracer {
	if name != Scope {
		return tracenoop.NewTracerProvider().Tracer(name)
	}
	return p.TracerProvider.Tracer(name, opts...)
}

// ExtractHTTP preserves W3C trace context without creating a span per request.
func ExtractHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))))
	})
}

// Lifecycle emits a constant-name control-flow span without payload attributes.
func Lifecycle(ctx context.Context, name string) {
	_, s := otel.Tracer(Scope).Start(ctx, name)
	s.End()
}

// Export-level severity and shape filtering applies independently of stdout.
// Even accidental calls in this scope cannot export arbitrary attributes.
type safeLogger struct{ log.Logger }

func (l safeLogger) Enabled(ctx context.Context, p log.EnabledParameters) bool {
	return p.Severity >= log.SeverityWarn && l.Logger.Enabled(ctx, p)
}
func (l safeLogger) Emit(ctx context.Context, r log.Record) {
	if r.Severity() < log.SeverityWarn || r.Body().AsString() != "scan requires investigation" {
		return
	}
	var safe log.Record
	safe.SetTimestamp(r.Timestamp())
	safe.SetSeverity(r.Severity())
	safe.SetBody(r.Body())
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		if kv.Key == "outcome" && (kv.Value.AsString() == "slow" || kv.Value.AsString() == "failed") {
			safe.AddAttributes(kv)
		}
		if kv.Key == "duration_seconds" && kv.Value.Type() == attribute.FLOAT64 {
			safe.AddAttributes(kv)
		}
		return true
	})
	l.Logger.Emit(ctx, safe)
}
