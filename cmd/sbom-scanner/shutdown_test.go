package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// blockingScanner is a minimal SBOMScannerServer whose Health call blocks until release is
// closed, standing in for a CreateSBOM call that outlives shutdown.
type blockingScanner struct {
	pb.UnimplementedSBOMScannerServer
	started chan struct{}
	release chan struct{}
}

func (b *blockingScanner) Health(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	close(b.started)
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &pb.HealthResponse{Ready: true}, nil
}

// TestGracefulStopWithTimeout_ForcesStopWhenRPCOutlivesTimeout guards #627: without a bound,
// GracefulStop waits for an in-flight RPC to return on its own -- which for CreateSBOM can be
// as long as the caller-supplied TimeoutSeconds. gracefulStopWithTimeout must force the
// connection closed once its own timeout elapses, regardless of how long the RPC keeps running.
func TestGracefulStopWithTimeout_ForcesStopWhenRPCOutlivesTimeout(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	scanner := &blockingScanner{started: make(chan struct{}), release: make(chan struct{})}
	pb.RegisterSBOMScannerServer(srv, scanner)
	defer close(scanner.release)

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewSBOMScannerClient(conn)

	callDone := make(chan error, 1)
	go func() {
		_, callErr := client.Health(context.Background(), &pb.HealthRequest{})
		callDone <- callErr
	}()

	select {
	case <-scanner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("RPC never reached the server")
	}

	const timeout = 200 * time.Millisecond
	start := time.Now()
	gracefulStopWithTimeout(srv, timeout)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("gracefulStopWithTimeout blocked for %s, expected it to force-stop near the %s timeout", elapsed, timeout)
	}

	select {
	case callErr := <-callDone:
		if callErr == nil {
			t.Fatal("expected the forcibly-stopped in-flight RPC to return an error")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight RPC never returned after forced Stop")
	}
}

// TestGracefulStopWithTimeout_ReturnsPromptlyWithNoInFlightRPCs is the counterpart to the
// force-stop case: with nothing in flight, GracefulStop returns almost immediately, and
// gracefulStopWithTimeout must not wait for its full timeout in that case.
func TestGracefulStopWithTimeout_ReturnsPromptlyWithNoInFlightRPCs(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterSBOMScannerServer(srv, sbomscanner.NewScannerServer())
	go func() { _ = srv.Serve(lis) }()

	const timeout = 5 * time.Second
	start := time.Now()
	gracefulStopWithTimeout(srv, timeout)
	elapsed := time.Since(start)

	if elapsed >= timeout/2 {
		t.Fatalf("gracefulStopWithTimeout took %s with no in-flight RPCs, expected it to return well under the %s timeout", elapsed, timeout)
	}
}

// TestRunServer_SignalTriggersCleanup verifies that receiving SIGTERM triggers graceful shutdown,
// removes the unix socket file, and stops the metrics HTTP server before exiting.
func TestRunServer_SignalTriggersCleanup(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test-scanner.sock")

	metricsLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port for metrics: %v", err)
	}
	metricsAddr := metricsLis.Addr().String()
	metricsLis.Close()

	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)

	go func() {
		errCh <- runServer(socketPath, metricsAddr, tempDir, sigCh)
	}()

	// Wait for socket file to be created
	socketReady := false
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			socketReady = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !socketReady {
		t.Fatalf("socket file %s was not created in time", socketPath)
	}

	// Verify metrics server is listening with bounded retry
	metricsClient := &http.Client{Timeout: 500 * time.Millisecond}
	metricsReady := false
	for i := 0; i < 50; i++ {
		resp, err := metricsClient.Get("http://" + metricsAddr + "/metrics")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				metricsReady = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !metricsReady {
		t.Fatalf("metrics server at %s was not ready in time", metricsAddr)
	}

	// Send SIGTERM signal to trigger shutdown
	sigCh <- syscall.SIGTERM

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runServer returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runServer did not shut down within 5 seconds of signal")
	}

	// Verify socket file was removed
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Errorf("socket file %s still exists after shutdown", socketPath)
	}

	// Verify metrics server is shut down
	metricsClosed := false
	for i := 0; i < 50; i++ {
		resp, err := metricsClient.Get("http://" + metricsAddr + "/metrics")
		if err != nil {
			metricsClosed = true
			break
		}
		_ = resp.Body.Close()
		time.Sleep(50 * time.Millisecond)
	}
	if !metricsClosed {
		t.Errorf("metrics server is still responding after shutdown")
	}
}
