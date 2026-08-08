package v1

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// maxUnixSockPathLen is the largest sockaddr_un.sun_path length (including the
// NUL terminator) that bind(2)/listen(2) will accept: 104 on Darwin, 108 on Linux.
func maxUnixSockPathLen() int {
	if runtime.GOOS == "darwin" {
		return 104
	}
	return 108
}

// newTestSocketPath returns a short-lived path for a Unix domain socket used in tests.
// t.TempDir() embeds the full test (and subtest) name, which on macOS's long default
// $TMPDIR can push the path past sun_path's limit and make net.Listen fail with a
// confusing "bind: invalid argument" unrelated to the test itself.
func newTestSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kv-sbom-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "s.sock")
	if max := maxUnixSockPathLen(); len(sock) >= max {
		t.Fatalf("socket path %q (%d bytes) exceeds sun_path limit (%d bytes) on %s", sock, len(sock), max, runtime.GOOS)
	}
	return sock
}

func startTestServer(t *testing.T) (pb.SBOMScannerClient, func()) {
	t.Helper()
	sock := newTestSocketPath(t)

	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxgRPCMessageSize),
		grpc.MaxSendMsgSize(MaxgRPCMessageSize),
	)
	pb.RegisterSBOMScannerServer(srv, NewScannerServer())
	go srv.Serve(lis)

	conn, err := grpc.NewClient("unix:"+sock,
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

// fakeAuthProvider is a scripted registryAuthProvider used to prove
// resolveSource consults registryAuthProviders generically, not just GCP.
type fakeAuthProvider struct {
	matchHost string
	creds     *image.RegistryCredentials
	err       error
}

func (p fakeAuthProvider) Matches(imageID string) bool {
	host, _, _ := strings.Cut(imageID, "/")
	return host == p.matchHost
}

func (p fakeAuthProvider) Credentials(ctx context.Context) (*image.RegistryCredentials, error) {
	return p.creds, p.err
}

func TestResolveSource_CustomProvider(t *testing.T) {
	orig := registryAuthProviders
	defer func() { registryAuthProviders = orig }()
	registryAuthProviders = []registryAuthProvider{
		fakeAuthProvider{
			matchHost: "my-registry.example.com",
			creds:     &image.RegistryCredentials{Username: "custom", Password: "token"},
		},
	}

	err401 := errors.New("401 Unauthorized")
	var calls [][]image.RegistryCredentials
	callCount := 0
	results := []error{err401, nil}
	get := func(ctx context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
		creds := append([]image.RegistryCredentials(nil), opts.Credentials...)
		calls = append(calls, creds)
		res := results[callCount]
		callCount++
		return nil, res
	}

	_, err := resolveSource(context.Background(), get, "my-registry.example.com/foo/bar", "", image.RegistryOptions{})
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
	assert.Equal(t, []image.RegistryCredentials{{Username: "custom", Password: "token"}}, calls[len(calls)-1])
}

func makeDummyTarGz(fileSize int) ([]byte, string, string, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	header := &tar.Header{
		Name: "dummy.txt",
		Mode: 0600,
		Size: int64(fileSize),
	}
	if err := tw.WriteHeader(header); err != nil {
		return nil, "", "", err
	}

	data := bytes.Repeat([]byte("a"), fileSize)
	if _, err := tw.Write(data); err != nil {
		return nil, "", "", err
	}

	if err := tw.Close(); err != nil {
		return nil, "", "", err
	}
	if err := gw.Close(); err != nil {
		return nil, "", "", err
	}

	blobBytes := buf.Bytes()
	hash := sha256.Sum256(blobBytes)
	hashStr := fmt.Sprintf("%x", hash)

	var tarBuf bytes.Buffer
	tarTw := tar.NewWriter(&tarBuf)
	if err := tarTw.WriteHeader(header); err != nil {
		return nil, "", "", err
	}
	if _, err := tarTw.Write(data); err != nil {
		return nil, "", "", err
	}
	if err := tarTw.Close(); err != nil {
		return nil, "", "", err
	}
	tarHash := sha256.Sum256(tarBuf.Bytes())
	diffIdStr := fmt.Sprintf("%x", tarHash)

	return blobBytes, hashStr, diffIdStr, nil
}

func TestCreateSBOM_ImageTooLarge_LocalRegistry(t *testing.T) {
	layerBytes, layerHash, diffId, err := makeDummyTarGz(1000)
	require.NoError(t, err)

	configPayload := fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}`, diffId)
	configBytes := []byte(configPayload)
	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))

	// Start local mock registry
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/v2/test-image/manifests/latest" {
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Write([]byte(fmt.Sprintf(`{
				"schemaVersion": 2,
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"config": {
					"mediaType": "application/vnd.docker.container.image.v1+json",
					"size": %d,
					"digest": "sha256:%s"
				},
				"layers": [
					{
						"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
						"size": %d,
						"digest": "sha256:%s"
					}
				]
			}`, len(configBytes), configHash, len(layerBytes), layerHash)))
			return
		}
		if r.URL.Path == fmt.Sprintf("/v2/test-image/blobs/sha256:%s", configHash) {
			w.Write(configBytes)
			return
		}
		if r.URL.Path == fmt.Sprintf("/v2/test-image/blobs/sha256:%s", layerHash) {
			w.Write(layerBytes)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
		ImageId:         u.Host + "/test-image",
		ImageTag:        u.Host + "/test-image:latest",
		MaxImageSize:    1, // Exceeded by layer size
		InsecureUseHttp: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, helpersv1.TooLarge, resp.Status)
	assert.Equal(t, "image-too-large", resp.StatusReason)
	assert.Empty(t, resp.ErrorMessage)
}

// TestIsRegistryRateLimited is a regression test for the sidecar path losing registry
// rate-limit statuses: a 429 from the registry must be recognized so CreateSBOM can surface
// StatusReason == domain.ReasonTooManyRequests over gRPC, letting the caller
// (adapters/v1 SidecarSBOMAdapter.CreateSBOM) wrap the domain.ErrTooManyRequests sentinel and
// allow ScanService.checkCreateSBOM to record the backoff, the same way it already does for
// the in-process syft adapter.
//
// The typed-error cases alone are not enough to catch a regression here: stereoscope's
// registry provider formats the go-containerregistry pull error with %+v, not %w (see
// pkg/image/oci/registry_provider.go in the matthyx/stereoscope fork this repo replaces to),
// which severs the errors.As chain before a real pull error ever reaches this function. The
// "wrapped via stereoscope's real %+v formatting" cases below reproduce that exact chain.
func TestIsRegistryRateLimited(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "429 transport error",
			err:  &transport.Error{StatusCode: http.StatusTooManyRequests},
			want: true,
		},
		{
			name: "429 transport error wrapped with %w",
			err:  fmt.Errorf("pulling image: %w", &transport.Error{StatusCode: http.StatusTooManyRequests}),
			want: true,
		},
		{
			name: "401 transport error is not rate limiting",
			err:  &transport.Error{StatusCode: http.StatusUnauthorized},
			want: false,
		},
		{
			name: "generic message mentioning 429 alone is not enough",
			err:  errors.New("received status code: 429"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "wrapped via stereoscope's real %+v formatting, empty response body",
			err:  fmt.Errorf("failed to get image descriptor from registry: %+v", &transport.Error{StatusCode: http.StatusTooManyRequests}),
			want: true,
		},
		{
			name: "wrapped via stereoscope's real %+v formatting, Docker Hub TOOMANYREQUESTS body",
			err: fmt.Errorf("failed to get image descriptor from registry: %+v", &transport.Error{
				StatusCode: http.StatusTooManyRequests,
				Errors: []transport.Diagnostic{
					{Code: transport.TooManyRequestsErrorCode, Message: "You have reached your pull rate limit."},
				},
			}),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRegistryRateLimited(tt.err))
		})
	}
}
