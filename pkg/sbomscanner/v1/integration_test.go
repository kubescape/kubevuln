package v1

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func startIntegrationServer(t *testing.T, opts ...ServerOption) (*sbomScannerClient, *grpc.Server, string) {
	t.Helper()
	return startIntegrationServerWith(t, NewScannerServer(opts...))
}

func startIntegrationServerWith(t *testing.T, impl pb.SBOMScannerServer) (*sbomScannerClient, *grpc.Server, string) {
	t.Helper()
	sock := newTestSocketPath(t)

	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxgRPCMessageSize),
		grpc.MaxSendMsgSize(MaxgRPCMessageSize),
	)
	pb.RegisterSBOMScannerServer(srv, impl)
	go func() {
		// Serve returns ErrServerStopped on the graceful Stop below; nothing else to do
		// with it here, but ignoring it silently is what errcheck flags.
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient("unix:"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxgRPCMessageSize),
			grpc.MaxCallSendMsgSize(MaxgRPCMessageSize),
		),
	)
	require.NoError(t, err)

	client := &sbomScannerClient{
		conn:   conn,
		client: pb.NewSBOMScannerClient(conn),
	}

	return client, srv, sock
}

// blockingScannerServer holds every scan until the server is stopped, so a test can take
// the transport away from under a running call.
type blockingScannerServer struct {
	pb.UnimplementedSBOMScannerServer
	started chan struct{}
}

func (s *blockingScannerServer) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Version: "test", Ready: true}, nil
}

func (s *blockingScannerServer) CreateSBOM(ctx context.Context, _ *pb.CreateSBOMRequest) (*pb.CreateSBOMResponse, error) {
	close(s.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestIntegration_HealthCheck(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer srv.Stop()
	defer os.Remove(sock)
	defer client.Close()

	assert.True(t, client.Ready())

	version, ready, err := client.Health(context.Background())
	require.NoError(t, err)
	assert.True(t, ready)
	assert.NotEmpty(t, version)
}

func TestIntegration_SimulatedTransportLoss(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer os.Remove(sock)
	defer client.Close()

	assert.True(t, client.Ready())

	// Stop the server to simulate a sidecar that is down before the scan starts, and wait
	// until the client has seen the transport go so the call below cannot ride on it.
	srv.Stop()
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for client.conn.GetState() == connectivity.Ready {
		require.True(t, client.conn.WaitForStateChange(waitCtx, connectivity.Ready), "connection never left Ready after the server stopped")
	}

	_, err := client.CreateSBOM(context.Background(), ScanRequest{
		ImageID:      "sha256:abc",
		ImageTag:     "test:latest",
		Options:      domain.RegistryOptions{},
		MaxImageSize: 1024 * 1024 * 1024,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScannerUnavailable)
	assert.NotErrorIs(t, err, ErrScannerLost)
	assert.NotErrorIs(t, err, ErrScannerCrashed)
}

func TestIntegration_ServerLostDuringScanIsLost(t *testing.T) {
	for _, warm := range []bool{true, false} {
		t.Run(map[bool]string{true: "connection ready before the call", false: "connection idle before the call"}[warm], func(t *testing.T) {
			impl := &blockingScannerServer{started: make(chan struct{})}
			client, srv, sock := startIntegrationServerWith(t, impl)
			defer os.Remove(sock)
			defer client.Close()

			if warm {
				require.True(t, client.Ready())
			}
			assertServerLostDuringScanIsLost(t, client, srv, impl)
		})
	}
}

func assertServerLostDuringScanIsLost(t *testing.T, client *sbomScannerClient, srv *grpc.Server, impl *blockingScannerServer) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		_, err := client.CreateSBOM(context.Background(), ScanRequest{
			ImageID:      "sha256:abc",
			ImageTag:     "test:latest",
			MaxImageSize: 1024 * 1024 * 1024,
		})
		errCh <- err
	}()

	select {
	case <-impl.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan never reached the server")
	}
	srv.Stop()

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrScannerLost)
		assert.NotErrorIs(t, err, ErrScannerUnavailable)
		assert.NotErrorIs(t, err, ErrScannerCrashed)
	case <-time.After(5 * time.Second):
		t.Fatal("CreateSBOM did not return after the server stopped")
	}
}

func TestIntegration_ReadyCheck(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer os.Remove(sock)

	assert.True(t, client.Ready())

	srv.Stop()

	assert.False(t, client.Ready())

	client.Close()
}

func TestNewSBOMScannerClient_CancelableReadinessWait(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "unreachable.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	client, err := NewSBOMScannerClient(ctx, sock, DefaultReadinessTimeout)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, client)
	assert.Less(t, elapsed, 5*time.Second, "readiness wait must return on the caller's context, not on the readiness timeout")
}
