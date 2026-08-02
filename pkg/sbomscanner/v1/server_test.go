package v1

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
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

	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxgRPCMessageSize),
		grpc.MaxSendMsgSize(MaxgRPCMessageSize),
	)
	pb.RegisterSBOMScannerServer(srv, NewScannerServer())
	go srv.Serve(lis)

	conn, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxgRPCMessageSize),
			grpc.MaxCallSendMsgSize(MaxgRPCMessageSize),
		),
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

func TestIsGCPRegistry(t *testing.T) {
	tests := []struct {
		imageID string
		want    bool
	}{
		{"gcr.io/foo/bar", true},
		{"us.gcr.io/foo/bar", true},
		{"us-docker.pkg.dev/foo/bar", true},
		{"europe-west1-docker.pkg.dev/project/repo/image:tag", true},
		{"quay.io/foo/bar", false},
		{"quay.io/foo/bar-docker.pkg.dev/x", false},
		{"index.docker.io/library/alpine", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.imageID, func(t *testing.T) {
			assert.Equal(t, tt.want, isGCPRegistry(tt.imageID))
		})
	}
}

func TestResolveSource(t *testing.T) {
	err401 := errors.New("401 Unauthorized")
	err403 := errors.New("403 Forbidden")
	manifestUnknownErr := errors.New("MANIFEST_UNKNOWN")

	tests := []struct {
		name            string
		imageID         string
		imageTag        string
		results         []error
		adcErr          error
		wantCalls       int
		wantLastCreds   []image.RegistryCredentials
		wantErr         bool
		wantErrIs       error
		wantErrContains string
		wantRefs        []string
	}{
		{
			name:      "non-GCP image + 401 falls back to anonymous",
			imageID:   "docker.io/library/nginx",
			results:   []error{err401, err403},
			wantCalls: 2,
			wantErr:   true,
		},
		{
			name:      "GCP image, ADC unavailable, falls back to anonymous",
			imageID:   "gcr.io/project/image",
			results:   []error{err401, err403},
			adcErr:    errors.New("ADC unavailable"),
			wantCalls: 2,
			wantErr:   true,
		},
		{
			name:    "GCP image, ADC available, retry succeeds",
			imageID: "gcr.io/project/image",
			results: []error{err401, nil},
			wantLastCreds: []image.RegistryCredentials{
				{Username: "oauth2accesstoken", Password: "token"},
			},
			wantCalls: 2,
		},
		{
			name:      "GCP image, ADC succeeds but pull fails non-401, still anonymous and restores Unauthorize",
			imageID:   "gcr.io/project/image",
			results:   []error{err401, err403, err403},
			wantCalls: 3,
			wantErr:   true,
			wantErrIs: err401,
		},
		{
			name:     "MANIFEST_UNKNOWN on imageID, 401 on imageTag, retries use imageTag",
			imageID:  "gcr.io/project/image@sha256:abc",
			imageTag: "gcr.io/project/image:latest",
			results:  []error{manifestUnknownErr, err401, err403, err403},
			wantRefs: []string{
				"gcr.io/project/image@sha256:abc",
				"gcr.io/project/image:latest",
				"gcr.io/project/image:latest",
				"gcr.io/project/image:latest",
			},
			wantCalls: 4,
			wantErr:   true,
			wantErrIs: err401,
		},
		{
			name:            "too-large during anonymous retry is not masked by original 401",
			imageID:         "gcr.io/project/image",
			adcErr:          errors.New("ADC unavailable"),
			results:         []error{err401, image.ErrImageTooLarge},
			wantCalls:       2,
			wantErr:         true,
			wantErrContains: image.ErrImageTooLarge.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := gcpCredsFn
			defer func() { gcpCredsFn = orig }()
			gcpCredsFn = func(ctx context.Context) (*image.RegistryCredentials, error) {
				if tt.adcErr != nil {
					return nil, tt.adcErr
				}
				return &image.RegistryCredentials{Username: "oauth2accesstoken", Password: "token"}, nil
			}

			var calls [][]image.RegistryCredentials
			var refs []string
			callCount := 0
			get := func(ctx context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
				refs = append(refs, ref)
				creds := append([]image.RegistryCredentials(nil), opts.Credentials...)
				calls = append(calls, creds)
				res := tt.results[callCount]
				callCount++
				return nil, res
			}

			_, err := resolveSource(context.Background(), get, tt.imageID, tt.imageTag, image.RegistryOptions{})
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.wantErrIs != nil {
				assert.ErrorIs(t, err, tt.wantErrIs)
			}
			if tt.wantErrContains != "" {
				assert.Contains(t, err.Error(), tt.wantErrContains)
			}
			assert.Equal(t, tt.wantCalls, callCount)
			if tt.wantLastCreds != nil {
				assert.Equal(t, tt.wantLastCreds, calls[len(calls)-1])
			}
			if tt.wantRefs != nil {
				assert.Equal(t, tt.wantRefs, refs)
			}
		})
	}
}
