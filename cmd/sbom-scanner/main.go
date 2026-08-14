package main

import (
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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

	// Remove stale socket file from a previous run
	os.Remove(socketPath)

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.L().Fatal("failed to listen on socket", helpers.Error(err), helpers.String("path", socketPath))
	}

	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(sbomscanner.MaxgRPCMessageSize),
		grpc.MaxSendMsgSize(sbomscanner.MaxgRPCMessageSize),
	)
	pb.RegisterSBOMScannerServer(srv, sbomscanner.NewScannerServer())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		logger.L().Info("received signal, shutting down", helpers.String("signal", sig.String()))
		gracefulStopWithTimeout(srv, shutdownTimeout)
		os.Remove(socketPath)
	}()

	logger.L().Info("SBOM scanner sidecar started", helpers.String("socket", socketPath))
	if err := srv.Serve(lis); err != nil {
		logger.L().Fatal("gRPC server failed", helpers.Error(err))
	}
}
