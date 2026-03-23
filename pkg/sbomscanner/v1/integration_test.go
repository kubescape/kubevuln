package v1

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func startIntegrationServer(t *testing.T) (SBOMScannerClient, *grpc.Server, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "scanner.sock")

	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	srv := grpc.NewServer()
	pb.RegisterSBOMScannerServer(srv, NewScannerServer())
	go srv.Serve(lis)

	conn, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client := &sbomScannerClient{
		conn:   conn,
		client: pb.NewSBOMScannerClient(conn),
	}

	return client, srv, sock
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

func TestIntegration_SimulatedCrash(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer os.Remove(sock)
	defer client.Close()

	assert.True(t, client.Ready())

	// Kill the server to simulate OOM
	srv.Stop()

	_, err := client.CreateSBOM(context.Background(), ScanRequest{
		ImageID:      "sha256:abc",
		ImageTag:     "test:latest",
		Options:      domain.RegistryOptions{},
		MaxImageSize: 1024 * 1024 * 1024,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScannerCrashed)
}

func TestIntegration_ReadyCheck(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer os.Remove(sock)

	assert.True(t, client.Ready())

	srv.Stop()

	assert.False(t, client.Ready())

	client.Close()
}
