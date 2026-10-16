package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/go-logger/otelsetup"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func cleanEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_COLLECTOR_SVC", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_SDK_DISABLED"} {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))
	}
}
func TestEndpointPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		value      *string
		discovered string
		want       string
		calls      int
	}{
		{"unset", nil, "otel.test:443", "https://otel.test:443", 1},
		{"empty", ptr(""), "ignored", "", 0},
		{"explicit", ptr("http://local:4317"), "ignored", "http://local:4317", 0},
		{"disable", ptr(" DiSaBlE "), "ignored", "", 0},
		{"scheme preserved", nil, "http://local:4317", "http://local:4317", 1},
		{"missing metrics", nil, "", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			t.Setenv("OTEL_EVENTS_EXPORTER_ENDPOINT", "events.test:443")
			if tc.value != nil {
				t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", *tc.value)
			}
			calls := 0
			err := ConfigureEndpoint(context.Background(), func(ctx context.Context) (string, error) {
				calls++
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.LessOrEqual(t, time.Until(deadline), 3*time.Second)
				return tc.discovered, nil
			})
			require.NoError(t, err)
			require.Equal(t, tc.calls, calls)
			require.Equal(t, tc.want, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
			require.Equal(t, "events.test:443", os.Getenv("OTEL_EVENTS_EXPORTER_ENDPOINT"))
		})
	}
}
func ptr(s string) *string { return &s }
func TestOptOutClearsAllOperationalEndpoints(t *testing.T) {
	cleanEnv(t)
	for _, key := range []string{"OTEL_COLLECTOR_SVC", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"} {
		t.Setenv(key, "http://local:4317")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "disable")
	require.NoError(t, ConfigureEndpoint(context.Background(), func(context.Context) (string, error) { t.Fatal("opt-out discovered"); return "", nil }))
	for _, key := range []string{"OTEL_COLLECTOR_SVC", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"} {
		require.Empty(t, os.Getenv(key))
	}
}
func TestDiscoveryFailureNonfatal(t *testing.T) {
	cleanEnv(t)
	want := errors.New("unavailable")
	require.ErrorIs(t, ConfigureEndpoint(context.Background(), func(context.Context) (string, error) { return "", want }), want)
	_, present := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT")
	require.False(t, present)
}
func TestLegacyAndSDKDisabled(t *testing.T) {
	cleanEnv(t)
	t.Setenv("OTEL_COLLECTOR_SVC", "legacy:4317")
	require.NoError(t, ConfigureEndpoint(context.Background(), nil))
	require.Equal(t, "legacy:4317", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	t.Setenv("OTEL_SDK_DISABLED", "true")
	require.NoError(t, ConfigureEndpoint(context.Background(), nil))
	require.Empty(t, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
}
func TestDefaultsPreserveExplicitSettings(t *testing.T) {
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "120000")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	Defaults()
	require.Equal(t, "120000", os.Getenv("OTEL_METRIC_EXPORT_INTERVAL"))
	require.Equal(t, "always_off", os.Getenv("OTEL_TRACES_SAMPLER"))
}
func TestInitRestoresEnvironmentAndNoop(t *testing.T) {
	cleanEnv(t)
	t.Setenv("OTEL_COLLECTOR_SVC", "legacy-ignored")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("KS_LOGGER_LEVEL", "debug")
	stop, err := Init(context.Background(), otelsetup.ProviderConfig{ServiceName: "kubevuln"})
	require.NoError(t, err)
	require.Equal(t, "legacy-ignored", os.Getenv("OTEL_COLLECTOR_SVC"))
	require.Equal(t, "debug", os.Getenv("KS_LOGGER_LEVEL"))
	require.NoError(t, stop(context.Background()))
}
func TestDiagnosticGateConcurrentBurst(t *testing.T) {
	g := &gate{}
	now := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for range 10000 {
		wg.Go(func() {
			if g.allow(now) {
				mu.Lock()
				count++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	require.Equal(t, 1, count)
	require.False(t, g.allow(now.Add(59*time.Second)))
	require.True(t, g.allow(now.Add(time.Minute)))
}

type captureLogger struct {
	noop.Logger
	records []log.Record
}

func (l *captureLogger) Emit(_ context.Context, r log.Record) { l.records = append(l.records, r) }
func TestExportLevelAndAttributeFilter(t *testing.T) {
	l := &captureLogger{}
	safe := safeLogger{Logger: l}
	var r log.Record
	r.SetBody(attribute.StringValue("scan requires investigation"))
	r.SetSeverity(log.SeverityInfo)
	safe.Emit(context.Background(), r)
	require.Empty(t, l.records)
	r.SetSeverity(log.SeverityWarn)
	r.AddAttributes(attribute.String("credential", "do-not-export"), attribute.String("outcome", "failed"))
	safe.Emit(context.Background(), r)
	require.Len(t, l.records, 1)
	require.Equal(t, 1, l.records[0].AttributesLen())
	r.SetBody(attribute.StringValue("attacker-controlled error"))
	safe.Emit(context.Background(), r)
	require.Len(t, l.records, 1)
}
func TestScopeFilter(t *testing.T) {
	old := otel.GetLoggerProvider()
	defer otel.SetLoggerProvider(old)
	p := &safeLogs{LoggerProvider: old}
	require.False(t, p.Logger("foreign").Enabled(context.Background(), log.EnabledParameters{Severity: log.SeverityError}))
	_, s := (&safeTraces{TracerProvider: otel.GetTracerProvider()}).Tracer("foreign").Start(context.Background(), "unreviewed")
	require.False(t, s.IsRecording())
}
func TestHTTPContextPropagation(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	parent := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled})
	req := httptest.NewRequest("POST", "http://localhost/scan", nil).WithContext(trace.ContextWithSpanContext(context.Background(), parent))
	InjectHTTP(req)
	require.NotEmpty(t, req.Header.Get("traceparent"))
	handler := ExtractHTTP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		require.Equal(t, parent.TraceID(), trace.SpanContextFromContext(r.Context()).TraceID())
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestGRPCContextPropagation(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	parent := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled})
	ctx := trace.ContextWithSpanContext(context.Background(), parent)
	err := UnaryClientContext(ctx, "/scanner/CreateSBOM", nil, nil, nil, func(out context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, _ := metadata.FromOutgoingContext(out)
		_, err := UnaryServerContext(metadata.NewIncomingContext(context.Background(), md), nil, &grpc.UnaryServerInfo{}, func(in context.Context, _ any) (any, error) {
			require.Equal(t, parent.TraceID(), trace.SpanContextFromContext(in).TraceID())
			return nil, nil
		})
		return err
	})
	require.NoError(t, err)
}
