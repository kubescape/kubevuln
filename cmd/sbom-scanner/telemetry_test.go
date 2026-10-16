package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/stretchr/testify/require"
	metricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
)

type finalMetricReceiver struct {
	metricpb.UnimplementedMetricsServiceServer
	removed atomic.Int64
}

func (r *finalMetricReceiver) Export(_ context.Context, req *metricpb.ExportMetricsServiceRequest) (*metricpb.ExportMetricsServiceResponse, error) {
	for _, rm := range req.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name == "kubevuln_temp_dir_sweep_removed_total" {
					for _, p := range m.GetSum().DataPoints {
						r.removed.Add(p.GetAsInt())
					}
				}
			}
		}
	}
	return &metricpb.ExportMetricsServiceResponse{}, nil
}

// The interval cannot elapse in this test: only runServer's final flush can
// deliver the observation made after RPC draining and before returning.
func TestRunServerFlushesFinalOTLPMetrics(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	receiver := &finalMetricReceiver{}
	collector := grpc.NewServer()
	metricpb.RegisterMetricsServiceServer(collector, receiver)
	go func() { _ = collector.Serve(listener) }()
	defer collector.Stop()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://"+listener.Addr().String())
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "3600000")
	saved := onMetricsShutdownStart
	defer func() { onMetricsShutdownStart = saved }()
	onMetricsShutdownStart = func() { metrics.RecordTempDirSweep(context.Background(), metrics.ComponentSidecar, 7) }
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	require.NoError(t, runServer(filepath.Join(t.TempDir(), "scanner.sock"), "127.0.0.1:0", t.TempDir(), signals))
	require.Equal(t, int64(7), receiver.removed.Load())
}
