package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/tools"
	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"google.golang.org/grpc"

	// Register a pure-Go sqlite driver under the name "sqlite". Syft's RPM
	// (redhat) cataloger requires it to read newer sqlite-backed RPM databases
	// (rpmdb.sqlite) found in recent RPM-based images. Unlike the main HTTP
	// binary, this sidecar does not import grype, so it does not transitively
	// pull a sqlite driver; without this import the cataloger fails with
	// "sqlite driver is required for cataloging newer RPM databases, none
	// registered". See https://github.com/kubescape/kubevuln/issues/378.
	_ "modernc.org/sqlite"
)

// shutdownTimeout bounds how long gracefulStopWithTimeout waits for in-flight CreateSBOM RPCs
// to finish on their own before forcing the connection closed. Matches cmd/http/main.go's
// shutdownTimeout default so both processes give a comparable grace period before a
// terminationGracePeriodSeconds-driven SIGKILL would otherwise cut them off mid-shutdown.
const shutdownTimeout = 20 * time.Second

// tempDirSweepInterval bounds how long a stereoscope temp dir leaked by this process (e.g. a
// registry pull that fails after the image temp dir is created but before there's an
// image.Image to Cleanup() it -- see internal/tools.StartPeriodicTempDirSweep) can sit on disk
// before being reclaimed. This process has no config file of its own (unlike cmd/http, which
// derives the same cadence from ScanTimeout), so it uses the same 5-minute value CreateSBOM
// already falls back to when a request carries no TimeoutSeconds (pkg/sbomscanner/v1/server.go).
const tempDirSweepInterval = 5 * time.Minute

// defaultMetricsAddr is the listen address for the Prometheus /metrics endpoint, used when
// METRICS_ADDR is unset. Overridable per-deployment via METRICS_ADDR, mirroring SOCKET_PATH
// below. Deliberately not :8080: this process runs as a sidecar container in the same Pod as
// cmd/http, which binds :8080 for its own server (also serving /metrics there). Containers in
// a Pod share one network namespace, so both processes defaulting to :8080 would collide --
// this one would fail to bind and its component="sidecar" metrics, including
// kubevuln_temp_dir_sweep_removed_total, would silently never be served.
const defaultMetricsAddr = ":8081"

// gracefulStopWithTimeout waits up to timeout for srv's in-flight RPCs to finish via
// GracefulStop, then force-closes the server with Stop if the timeout elapses first.
//
// GracefulStop alone blocks until every in-flight RPC handler returns on its own. For
// CreateSBOM that can take as long as the caller-supplied TimeoutSeconds (5 minutes by
// default, see pkg/sbomscanner/v1/server.go) -- a per-call deadline with no awareness that
// the process is shutting down. Without this bound, shutdown time is dictated entirely by
// whatever timeout the in-flight request happened to carry, not by anything under this
// process's control. See #627.
func gracefulStopWithTimeout(srv *grpc.Server, timeout time.Duration) {
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		logger.L().Info("gRPC server stopped gracefully")
	case <-time.After(timeout):
		logger.L().Warning("graceful shutdown timeout reached, forcing stop",
			helpers.String("timeout", timeout.String()))
		srv.Stop()
	}
}

func main() {
	socketPath := os.Getenv("SOCKET_PATH")
	if socketPath == "" {
		socketPath = "/sbom-comm/scanner.sock"
	}
	socketPath = filepath.Clean(socketPath)

	// Remove stale socket file from a previous run
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) { // #nosec G703 -- SOCKET_PATH is operator-controlled deployment config; path is cleaned above
		logger.L().Warning("failed to remove stale socket file", helpers.Error(err), helpers.String("path", socketPath))
	}

	lis, err := net.Listen("unix", socketPath) // #nosec G703 -- SOCKET_PATH is operator-controlled deployment config, not untrusted input; path is cleaned above
	if err != nil {
		logger.L().Fatal("failed to listen on socket", helpers.Error(err), helpers.String("path", socketPath))
	}

	// Without this, RecordTempDirSweep below (and any other metrics.Record* called from the
	// sidecar's own code paths, e.g. adapters that run in-process here) reads a nil counter and
	// is a no-op: the component="sidecar" series would never be emitted, silently.
	m, err := metrics.New()
	if err != nil {
		logger.L().Fatal("metrics initialization error", helpers.Error(err))
	}
	metricsAddr := os.Getenv("METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = defaultMetricsAddr
	}
	metricsServer := &http.Server{
		Addr:              metricsAddr,
		Handler:           m.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.L().Warning("metrics server stopped unexpectedly", helpers.Error(err))
		}
	}()

	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(sbomscanner.MaxgRPCMessageSize),
		grpc.MaxSendMsgSize(sbomscanner.MaxgRPCMessageSize),
	)
	pb.RegisterSBOMScannerServer(srv, sbomscanner.NewScannerServer())

	// See tempDirSweepInterval: this process (unlike cmd/http) previously had no temp-dir
	// sweep at all, startup or periodic, despite being the one that performs pod-less
	// registry pulls (registry rescans, periodic CRD-based rescans).
	stopSweep := make(chan struct{})
	tools.StartPeriodicTempDirSweep(stopSweep, os.TempDir(), "stereoscope-", tempDirSweepInterval, tempDirSweepInterval, func(removed int, err error) {
		if err != nil {
			logger.L().Warning("temp dir sweep error", helpers.Error(err), helpers.Int("removed", removed))
		} else if removed > 0 {
			logger.L().Info("temp dir sweep complete", helpers.Int("removed", removed))
		}
		metrics.RecordTempDirSweep(context.Background(), metrics.ComponentSidecar, removed)
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		logger.L().Info("received signal, shutting down", helpers.String("signal", sig.String()))
		close(stopSweep)
		gracefulStopWithTimeout(srv, shutdownTimeout)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			logger.L().Warning("metrics server shutdown error", helpers.Error(err))
		}
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) { // #nosec G703 -- SOCKET_PATH is operator-controlled deployment config; path is cleaned above
			logger.L().Warning("failed to remove socket file on shutdown", helpers.Error(err), helpers.String("path", socketPath))
		}
	}()

	logger.L().Info("SBOM scanner sidecar started", helpers.String("socket", socketPath))
	if err := srv.Serve(lis); err != nil { // #nosec G703 -- see SOCKET_PATH note above
		logger.L().Fatal("gRPC server failed", helpers.Error(err))
	}
}
