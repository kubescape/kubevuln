package main

import (
	"context"
	"net"
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
