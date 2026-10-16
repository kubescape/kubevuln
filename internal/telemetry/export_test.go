package telemetry

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/go-logger/otelsetup"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	logpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/protobuf/proto"
)

type received struct {
	mu                                                                sync.Mutex
	metricBytes, traceBytes, logBytes, points, spans, logs, wireBytes int
	authorized                                                        bool
	violations                                                        []string
}
type mockMetrics struct {
	metricpb.UnimplementedMetricsServiceServer
	r *received
}

func (s *mockMetrics) Export(ctx context.Context, r *metricpb.ExportMetricsServiceRequest) (*metricpb.ExportMetricsServiceResponse, error) {
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	s.r.metricBytes += proto.Size(r)
	md, _ := metadata.FromIncomingContext(ctx)
	s.r.authorized = len(md.Get("x-api-key")) == 1 && md.Get("x-api-key")[0] == "test-key" && md.Get("x-api-account")[0] == "test-account"
	for _, rm := range r.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if h := m.GetHistogram(); h != nil {
					s.r.points += len(h.DataPoints)
					for _, p := range h.DataPoints {
						if m.Name == "kubevuln_scan_duration_seconds" && len(p.ExplicitBounds) != 12 {
							s.r.violations = append(s.r.violations, "histogram boundaries changed")
						}
					}
				}
				if sum := m.GetSum(); sum != nil {
					s.r.points += len(sum.DataPoints)
				}
				if g := m.GetGauge(); g != nil {
					s.r.points += len(g.DataPoints)
				}
			}
		}
	}
	return &metricpb.ExportMetricsServiceResponse{}, nil
}

type mockTraces struct {
	tracepb.UnimplementedTraceServiceServer
	r *received
}

func (s *mockTraces) Export(_ context.Context, r *tracepb.ExportTraceServiceRequest) (*tracepb.ExportTraceServiceResponse, error) {
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	s.r.traceBytes += proto.Size(r)
	for _, rs := range r.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			s.r.spans += len(ss.Spans)
		}
	}
	return &tracepb.ExportTraceServiceResponse{}, nil
}

type mockLogs struct {
	logpb.UnimplementedLogsServiceServer
	r *received
}

func (s *mockLogs) Export(_ context.Context, r *logpb.ExportLogsServiceRequest) (*logpb.ExportLogsServiceResponse, error) {
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	s.r.logBytes += proto.Size(r)
	for _, rl := range r.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			for _, record := range sl.LogRecords {
				if record.SeverityNumber < 13 || len(record.TraceId) != 16 || len(record.SpanId) != 8 {
					s.r.violations = append(s.r.violations, "unsafe or uncorrelated log")
				}
				s.r.logs++
			}
		}
	}
	return &logpb.ExportLogsServiceResponse{}, nil
}

type wireStats struct{ r *received }

func (w wireStats) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context { return ctx }
func (w wireStats) HandleRPC(_ context.Context, s stats.RPCStats) {
	if p, ok := s.(*stats.InPayload); ok {
		w.r.mu.Lock()
		w.r.wireBytes += p.WireLength
		w.r.mu.Unlock()
	}
}
func (w wireStats) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }
func (w wireStats) HandleConn(context.Context, stats.ConnStats)                       {}

// This is a synthetic measurement, not a representative scan/fleet budget.
// A real local OTLP/gRPC server receives compressed SDK exports without external services.
func TestExportVolume(t *testing.T) {
	for _, n := range []int{0, 10, 10000} {
		t.Run(stringName(n), func(t *testing.T) {
			cleanEnv(t)
			for key, value := range map[string]string{"OTEL_TRACES_SAMPLER": "always_on", "OTEL_EXPORTER_OTLP_COMPRESSION": "gzip", "OTEL_METRIC_EXPORT_INTERVAL": "3600000", "OTEL_BSP_SCHEDULE_DELAY": "3600000", "OTEL_BLRP_SCHEDULE_DELAY": "3600000"} {
				t.Setenv(key, value)
			}
			endpoint, r := newMockCollector(t)
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
			cfg := otelsetup.ProviderConfig{ServiceName: "kubevuln", ServiceVersion: "test", AccountID: "test-account", AccessKey: "test-key"}
			stop, err := Init(context.Background(), cfg)
			require.NoError(t, err)
			reader, err := metrics.OTLPReader(context.Background(), cfg)
			require.NoError(t, err)
			m, err := metrics.New(sdkmetric.WithReader(reader), sdkmetric.WithResource(resource.NewSchemaless(metrics.ResourceAttributes(cfg)...)))
			require.NoError(t, err)
			diagnosticGate = &gate{}
			events := n
			if events == 0 {
				events = 10
			}
			for range events {
				attrs := metric.WithAttributes(attribute.String("endpoint", "scanCVE"), attribute.String("outcome", func() string {
					if n == 0 {
						return "success"
					}
					return "error"
				}()), attribute.String("reason", "unexpected_error"))
				m.ScanCounter.Add(context.Background(), 1, attrs)
				m.ScanDuration.Record(context.Background(), 1, attrs)
				ScanDiagnostic(context.Background(), time.Now().Add(-time.Second), n != 0)
				var unsafe log.Record
				unsafe.SetSeverity(log.SeverityError)
				unsafe.SetBody(attribute.StringValue("secret-payload"))
				otel.GetLoggerProvider().Logger("application").Emit(context.Background(), unsafe)
			}
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, m.Shutdown(flushCtx))
			require.NoError(t, stop(flushCtx))
			r.mu.Lock()
			defer r.mu.Unlock()
			require.True(t, r.authorized)
			require.Empty(t, r.violations)
			expected := 1
			if n == 0 {
				expected = 0
			}
			require.Equal(t, expected, r.spans)
			require.Equal(t, expected, r.logs)
			require.Equal(t, 4, r.points)
			require.Positive(t, r.wireBytes)
			t.Logf("events=%d metric_points=%d spans=%d logs=%d protobuf_bytes(metrics/traces/logs)=%d/%d/%d compressed_grpc_payload_bytes=%d", events, r.points, r.spans, r.logs, r.metricBytes, r.traceBytes, r.logBytes, r.wireBytes)
		})
	}
}
func stringName(n int) string {
	if n == 0 {
		return "normal-success-10"
	}
	if n == 10 {
		return "failures-10"
	}
	return "burst-10000"
}

func TestBackendOutageDoesNotBlockProcessing(t *testing.T) {
	cleanEnv(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	endpoint := "http://" + listener.Addr().String()
	require.NoError(t, listener.Close())
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	stop, err := Init(context.Background(), otelsetup.ProviderConfig{ServiceName: "kubevuln"})
	require.NoError(t, err)
	reader, err := metrics.OTLPReader(context.Background(), otelsetup.ProviderConfig{ServiceName: "kubevuln"})
	require.NoError(t, err)
	m, err := metrics.New(sdkmetric.WithReader(reader))
	require.NoError(t, err)
	diagnosticGate = &gate{}
	start := time.Now()
	for range 10000 {
		m.ScanCounter.Add(context.Background(), 1)
		ScanDiagnostic(context.Background(), start, true)
	}
	require.Less(t, time.Since(start), time.Second, "core recording must not await backend")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = m.Shutdown(ctx)
	_ = stop(ctx)
	require.Less(t, time.Since(start), time.Second, "outage flush must honor shutdown deadline")
}

func newMockCollector(t *testing.T) (string, *received) {
	t.Helper()
	r := &received{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer(grpc.StatsHandler(wireStats{r}))
	metricpb.RegisterMetricsServiceServer(server, &mockMetrics{r: r})
	tracepb.RegisterTraceServiceServer(server, &mockTraces{r: r})
	logpb.RegisterLogsServiceServer(server, &mockLogs{r: r})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return "http://" + listener.Addr().String(), r
}

func TestPerSignalEndpointOverride(t *testing.T) {
	cleanEnv(t)
	base, baseReceived := newMockCollector(t)
	override, metricReceived := newMockCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", base)
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", override)
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	cfg := otelsetup.ProviderConfig{ServiceName: "kubevuln"}
	stop, err := Init(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, override, os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"))
	reader, err := metrics.OTLPReader(context.Background(), cfg)
	require.NoError(t, err)
	m, err := metrics.New(sdkmetric.WithReader(reader))
	require.NoError(t, err)
	m.ScanCounter.Add(context.Background(), 1)
	Lifecycle(context.Background(), "kubevuln.startup")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, m.Shutdown(ctx))
	require.NoError(t, stop(ctx))
	baseReceived.mu.Lock()
	defer baseReceived.mu.Unlock()
	metricReceived.mu.Lock()
	defer metricReceived.mu.Unlock()
	require.Equal(t, 0, baseReceived.points)
	require.Equal(t, 1, baseReceived.spans)
	require.Equal(t, 3, metricReceived.points)
	require.Equal(t, 0, metricReceived.spans)
}
