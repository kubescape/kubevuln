package v1

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func startTestServer(t *testing.T) (pb.SBOMScannerClient, func()) {
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

	client := pb.NewSBOMScannerClient(conn)
	cleanup := func() {
		conn.Close()
		srv.Stop()
		os.Remove(sock)
	}
	return client, cleanup
}

func TestHealth(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.Health(context.Background(), &pb.HealthRequest{})
	require.NoError(t, err)
	assert.True(t, resp.Ready)
	assert.NotEmpty(t, resp.Version)
}

func TestCreateSBOM_ContextCancelled(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resp, err := client.CreateSBOM(ctx, &pb.CreateSBOMRequest{
		ImageId:  "test-image",
		ImageTag: "test:latest",
	})
	assert.Nil(t, resp)
	require.Error(t, err)
}

func TestNormalizeImageID(t *testing.T) {
	tests := []struct {
		name     string
		imageID  string
		imageTag string
		expected string
	}{
		{
			name:     "empty imageID uses imageTag",
			imageID:  "",
			imageTag: "nginx:latest",
			expected: "nginx:latest",
		},
		{
			name:     "full digest reference",
			imageID:  "docker.io/library/nginx@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd",
			imageTag: "nginx:latest",
			expected: "docker.io/library/nginx@sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeImageID(tt.imageID, tt.imageTag)
			assert.Equal(t, tt.expected, result)
		})
	}
}
