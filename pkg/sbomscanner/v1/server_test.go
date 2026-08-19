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
	"sync"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/gofrs/flock"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/registryauth"
	"github.com/kubescape/kubevuln/internal/tools"
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
			orig := registryauth.GCPCredsFn
			defer func() { registryauth.GCPCredsFn = orig; registryauth.ResetCaches() }()
			registryauth.ResetCaches()
			registryauth.GCPCredsFn = func(ctx context.Context) (*image.RegistryCredentials, time.Time, error) {
				if tt.adcErr != nil {
					return nil, time.Time{}, tt.adcErr
				}
				return &image.RegistryCredentials{Username: "oauth2accesstoken", Password: "token"}, time.Now().Add(time.Hour), nil
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

func TestResolveSource_RecordsFallbackMetrics(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)

	orig := registryauth.GCPCredsFn
	defer func() { registryauth.GCPCredsFn = orig; registryauth.ResetCaches() }()
	registryauth.ResetCaches()
	registryauth.GCPCredsFn = func(ctx context.Context) (*image.RegistryCredentials, time.Time, error) {
		return &image.RegistryCredentials{Username: "oauth2accesstoken", Password: "token"}, time.Now().Add(time.Hour), nil
	}

	callCount := 0
	get := func(ctx context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
		callCount++
		if callCount == 1 {
			return nil, errors.New("401 Unauthorized")
		}
		return nil, nil
	}

	_, err = resolveSource(context.Background(), get, "gcr.io/project/image", "", image.RegistryOptions{})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)
	body := w.Body.String()

	assert.True(t, strings.Contains(body, `kubevuln_scan_fallbacks_total{category="registry_auth",component="sidecar",outcome="succeeded",strategy="gcp_adc"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_scan_source_resolution_total{component="sidecar",outcome="fallback_assisted_success"} 1`), body)
}

func TestResolveSource_Retry429RateLimit(t *testing.T) {
	calls := 0
	get := func(ctx context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
		return tools.RetryWithBackoff(ctx, "test_retry", tools.FastRetryConfig(), tools.IsRateLimitError, func(retryCtx context.Context) (source.Source, error) {
			calls++
			if calls < 2 {
				return nil, &transport.Error{StatusCode: http.StatusTooManyRequests}
			}
			return nil, nil
		})
	}

	_, err := resolveSource(context.Background(), get, "my-image:latest", "my-image:latest", image.RegistryOptions{})
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
}

// fakeAuthProvider is a scripted registryauth.Provider used to prove
// resolveSource consults registryauth.Providers generically, not just GCP.
type fakeAuthProvider struct {
	matchHost string
	creds     *image.RegistryCredentials
	err       error
}

func (p fakeAuthProvider) Matches(imageID string) bool {
	host, _, _ := strings.Cut(imageID, "/")
	return host == p.matchHost
}

func (p fakeAuthProvider) Credentials(ctx context.Context, _ string) (*image.RegistryCredentials, error) {
	return p.creds, p.err
}

func (p fakeAuthProvider) Strategy() string { return "fake" }

func TestResolveSource_CustomProvider(t *testing.T) {
	orig := registryauth.Providers
	defer func() { registryauth.Providers = orig }()
	registryauth.Providers = []registryauth.Provider{
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

func TestResolveSource_ProviderNilCredentialsFallsBackAnonymous(t *testing.T) {
	orig := registryauth.Providers
	defer func() { registryauth.Providers = orig }()
	registryauth.Providers = []registryauth.Provider{
		fakeAuthProvider{matchHost: "my-registry.example.com"},
	}

	err401 := errors.New("401 Unauthorized")
	err403 := errors.New("403 Forbidden")
	var calls [][]image.RegistryCredentials
	callCount := 0
	results := []error{err401, err403}
	get := func(ctx context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
		creds := append([]image.RegistryCredentials(nil), opts.Credentials...)
		calls = append(calls, creds)
		res := results[callCount]
		callCount++
		return nil, res
	}

	assert.NotPanics(t, func() {
		_, err := resolveSource(context.Background(), get, "my-registry.example.com/foo/bar", "", image.RegistryOptions{})
		require.Error(t, err)
	})
	assert.Equal(t, 2, callCount)
	assert.Nil(t, calls[len(calls)-1])
}

func TestResolveSource_ProviderMatchesUsesPullRef(t *testing.T) {
	orig := registryauth.Providers
	defer func() { registryauth.Providers = orig }()
	registryauth.Providers = []registryauth.Provider{
		fakeAuthProvider{
			matchHost: "gcr.io",
			creds:     &image.RegistryCredentials{Username: "custom", Password: "token"},
		},
	}

	manifestUnknownErr := errors.New("MANIFEST_UNKNOWN")
	err401 := errors.New("401 Unauthorized")
	var calls [][]image.RegistryCredentials
	callCount := 0
	results := []error{manifestUnknownErr, err401, nil}
	get := func(ctx context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
		creds := append([]image.RegistryCredentials(nil), opts.Credentials...)
		calls = append(calls, creds)
		res := results[callCount]
		callCount++
		return nil, res
	}

	_, err := resolveSource(context.Background(), get, "digest-only.example.com/foo@sha256:abc", "gcr.io/foo:latest", image.RegistryOptions{})
	require.NoError(t, err)
	assert.Equal(t, 3, callCount)
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
		Platform:        "linux/amd64",
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
			name: "generic message mentioning 429",
			err:  errors.New("received status code: 429"),
			want: true,
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
			assert.Equal(t, tt.want, tools.IsRateLimitError(tt.err))
		})
	}
}

func TestIsPlatformMismatch(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "typed platform mismatch",
			err:  &image.ErrPlatformMismatch{ExpectedPlatform: "linux/arm64"},
			want: true,
		},
		{
			name: "wrapped typed platform mismatch",
			err:  fmt.Errorf("resolving source: %w", &image.ErrPlatformMismatch{ExpectedPlatform: "linux/arm64"}),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("mismatched platform mentioned but not the typed error"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPlatformMismatch(tt.err))
		})
	}
}

func TestFormatResolvedPlatform(t *testing.T) {
	tests := []struct {
		name    string
		os      string
		arch    string
		variant string
		want    string
	}{
		{name: "os and arch", os: "linux", arch: "amd64", want: "linux/amd64"},
		{name: "os, arch and variant", os: "linux", arch: "arm", variant: "v7", want: "linux/arm/v7"},
		{name: "neither known", want: ""},
		{name: "arch known, os unknown", arch: "amd64", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatResolvedPlatform(tt.os, tt.arch, tt.variant))
		})
	}
}

// TestCreateSBOM_PlatformMismatch_LocalRegistry is a regression test for #512: requesting a
// platform absent from the image's manifest must surface a distinct "platform not found"
// reason instead of falling into the generic error path.
func TestCreateSBOM_PlatformMismatch_LocalRegistry(t *testing.T) {
	layerBytes, layerHash, diffId, err := makeDummyTarGz(100)
	require.NoError(t, err)

	configPayload := fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}`, diffId)
	configBytes := []byte(configPayload)
	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/v2/test-image/manifests/latest":
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
		case r.URL.Path == fmt.Sprintf("/v2/test-image/blobs/sha256:%s", configHash):
			w.Write(configBytes)
		case r.URL.Path == fmt.Sprintf("/v2/test-image/blobs/sha256:%s", layerHash):
			w.Write(layerBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
		ImageId:         u.Host + "/test-image",
		ImageTag:        u.Host + "/test-image:latest",
		Platform:        "linux/arm64",
		MaxImageSize:    1 << 30,
		InsecureUseHttp: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Contains(t, resp.ErrorMessage, "mismatched platform")
	assert.Equal(t, domain.ReasonPlatformNotFound, resp.StatusReason)
	assert.Empty(t, resp.Status)
}

// TestCreateSBOM_PullTimeout_ReturnsIncompleteInsteadOfHanging is a regression test for #742: a
// registry that accepts the connection but never responds to the manifest request used to hang
// the pull - and the RPC with it - indefinitely, since neither the request context nor any
// deadline bounded resolveSource's call chain. The mock registry below blocks on the manifest
// request until the test explicitly releases it, simulating exactly that stalling registry.
// CreateSBOM must still return, bounded by TimeoutSeconds, well before that release happens.
func TestCreateSBOM_PullTimeout_ReturnsIncompleteInsteadOfHanging(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Never respond to the manifest request until the test releases it - a connection
		// that accepts the request but stalls, not one that errors or refuses outright.
		<-release
		w.WriteHeader(http.StatusNotFound)
	}))
	// close(release) must run before server.Close(), which blocks until the handler above
	// returns - deferred in this order so it does, since defers run LIFO.
	defer server.Close()
	defer close(release)

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, cleanup := startTestServer(t)
	defer cleanup()

	type result struct {
		resp *pb.CreateSBOMResponse
		err  error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		resp, err := client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
			ImageId:         u.Host + "/test-image",
			ImageTag:        u.Host + "/test-image:latest",
			Platform:        "linux/amd64",
			MaxImageSize:    1 << 30,
			MaxSbomSize:     1 << 30,
			TimeoutSeconds:  1,
			InsecureUseHttp: true,
		})
		done <- result{resp, err}
	}()

	select {
	case r := <-done:
		// Bounds the response to the configured 1s pull timeout plus CI scheduling
		// tolerance, not just "eventually" - a regression that returns after several
		// seconds instead of hanging forever would otherwise still pass.
		assert.Less(t, time.Since(start), 4*time.Second, "CreateSBOM should return shortly after the pull's TimeoutSeconds, not after an unrelated delay")
		require.NoError(t, r.err)
		require.NotNil(t, r.resp)
		assert.Equal(t, helpersv1.Incomplete, r.resp.Status, "a stalled pull must surface as Incomplete, the same status a cataloguing timeout already uses")
		assert.Empty(t, r.resp.ErrorMessage)
	case <-time.After(10 * time.Second):
		// Deadlock fallback only, well above the 4s bound asserted above: if the pull
		// truly never returns, fail with a clear message instead of hanging the suite.
		t.Fatal("CreateSBOM never returned after the pull's TimeoutSeconds elapsed - the pull is not bounded by any deadline")
	}
}

// activeScanLockPath must match internal/tools' own unexported activeScanLockPath(os.TempDir()):
// same directory (os.TempDir(), which BeginActiveTempDirUse is always called with in this
// package and adapters/v1), same filename. There is no exported way to ask tools for this path,
// so it is duplicated here deliberately, the same way #796's own evidence had to cite it as a
// literal to describe the mechanism from outside internal/tools.
func activeScanLockPathForTest() string {
	return filepath.Join(os.TempDir(), ".kubevuln-active-scan.lock")
}

// TestCreateSBOM_PullHoldsTempDirGuard is the regression test for #796: BeginActiveTempDirUse
// used to be registered only once the pull had already finished (right before cataloguing
// started), leaving the pull itself - which is what actually creates the stereoscope temp dir
// and downloads layers into it - completely unprotected against a concurrent
// StartPeriodicTempDirSweep pass in this process or the in-process adapter's, sharing the same
// os.TempDir(). This stalls a real pull mid-flight (the manifest request never completes until
// released) and, while it's stalled, asserts that a fresh, independent handle on the same
// cross-process lease file cannot take the exclusive lock StartPeriodicTempDirSweep's own
// acquireSweepLease needs before it will remove anything - proving the guard is held for the
// pull, not just for cataloguing afterward.
func TestCreateSBOM_PullHoldsTempDirGuard(t *testing.T) {
	// Both this test and its in-process counterpart (adapters/v1) contend for the same
	// process-global lease file under os.TempDir(), and go test runs packages as concurrent
	// processes. Redirect os.TempDir() to a directory private to this test - it reads TMPDIR
	// at call time - so the two can never observe each other's lease.
	t.Setenv("TMPDIR", t.TempDir())

	release := make(chan struct{})
	pullStarted := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Never respond to the manifest request until the test releases it - a connection
		// that accepts the request but stalls, not one that errors or refuses outright, so
		// the pull is genuinely still in flight while this test inspects the lease.
		once.Do(func() { close(pullStarted) })
		<-release
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, cleanup := startTestServer(t)
	defer cleanup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
			ImageId:         u.Host + "/test-image",
			ImageTag:        u.Host + "/test-image:latest",
			Platform:        "linux/amd64",
			MaxImageSize:    1 << 30,
			MaxSbomSize:     1 << 30,
			TimeoutSeconds:  30,
			InsecureUseHttp: true,
		})
	}()

	select {
	case <-pullStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("pull never reached the manifest request")
	}

	independentLease := flock.New(activeScanLockPathForTest())
	locked, lockErr := independentLease.TryLock()
	require.NoError(t, lockErr, "probing the sweep's exclusive lease must not itself fail")
	if locked {
		_ = independentLease.Unlock()
	}
	assert.False(t, locked, "a sweep's exclusive lease must not be acquirable while a pull is still in flight, before cataloguing has even started")

	close(release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("CreateSBOM never returned after the pull was released")
	}

	// The lease must be fully released once CreateSBOM has returned, so a genuinely stale
	// directory left by some other, truly abandoned run can still be swept afterward.
	require.Eventually(t, func() bool {
		l := flock.New(activeScanLockPathForTest())
		ok, lockErr := l.TryLock()
		if lockErr != nil {
			return false
		}
		if ok {
			_ = l.Unlock()
		}
		return ok
	}, 5*time.Second, 50*time.Millisecond, "the temp-dir guard must be released once CreateSBOM returns")
}

// TestCreateSBOM_TimeoutDoesNotRaceWithAbandonedSyft covers the deadline path: deadline.Run
// does not (and documents that it cannot) stop the work function, and Syft's cataloguers do
// not observe cancellation, so on timeout the Syft goroutine keeps running and finishes after
// the handler has already returned Incomplete.
//
// The work function must therefore share nothing with the handler. Run under -race, this test
// fails if the goroutine writes a variable the handler reads.
func TestCreateSBOM_TimeoutDoesNotRaceWithAbandonedSyft(t *testing.T) {
	layerBytes, layerHash, diffId, err := makeDummyTarGz(64)
	require.NoError(t, err)

	configPayload := fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}`, diffId)
	configBytes := []byte(configPayload)
	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/test-image/manifests/latest":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{
				"schemaVersion": 2,
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": %d, "digest": "sha256:%s"},
				"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": %d, "digest": "sha256:%s"}]
			}`, len(configBytes), configHash, len(layerBytes), layerHash)))
		case fmt.Sprintf("/v2/test-image/blobs/sha256:%s", configHash):
			_, _ = w.Write(configBytes)
		case fmt.Sprintf("/v2/test-image/blobs/sha256:%s", layerHash):
			_, _ = w.Write(layerBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	// Stand in for Syft: outlive the deadline, then return a result exactly as the real
	// cataloguer would once it finishes naturally.
	finished := make(chan struct{})
	orig := createSBOMFn
	defer func() { createSBOMFn = orig }()
	createSBOMFn = func(_ context.Context, _ source.Source, _ *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		time.Sleep(1500 * time.Millisecond)
		defer close(finished)
		return &sbom.SBOM{}, nil
	}

	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
		ImageId:         u.Host + "/test-image",
		ImageTag:        u.Host + "/test-image:latest",
		Platform:        "linux/amd64",
		MaxImageSize:    1 << 30,
		MaxSbomSize:     1 << 30,
		TimeoutSeconds:  1,
		InsecureUseHttp: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, helpersv1.Incomplete, resp.Status, "the deadline must surface as Incomplete")

	// Let the abandoned goroutine finish while the handler's result is being read, which is
	// the window the race lived in.
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("stand-in Syft never finished")
	}
	assert.Equal(t, helpersv1.Incomplete, resp.Status, "the late write must not affect the response")
}

func TestCreateSBOM_Exhausted429RateLimitFromCreateSBOMFn(t *testing.T) {
	layerBytes, layerHash, diffId, err := makeDummyTarGz(64)
	require.NoError(t, err)

	configPayload := fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}`, diffId)
	configBytes := []byte(configPayload)
	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/test-image-429/manifests/latest":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{
				"schemaVersion": 2,
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": %d, "digest": "sha256:%s"},
				"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": %d, "digest": "sha256:%s"}]
			}`, len(configBytes), configHash, len(layerBytes), layerHash)))
		case fmt.Sprintf("/v2/test-image-429/blobs/sha256:%s", configHash):
			_, _ = w.Write(configBytes)
		case fmt.Sprintf("/v2/test-image-429/blobs/sha256:%s", layerHash):
			_, _ = w.Write(layerBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	orig := createSBOMFn
	defer func() { createSBOMFn = orig }()
	createSBOMFn = func(_ context.Context, _ source.Source, _ *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		return nil, &transport.Error{StatusCode: http.StatusTooManyRequests}
	}

	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
		ImageId:         u.Host + "/test-image-429",
		ImageTag:        u.Host + "/test-image-429:latest",
		Platform:        "linux/amd64",
		MaxImageSize:    1 << 30,
		MaxSbomSize:     1 << 30,
		TimeoutSeconds:  30,
		InsecureUseHttp: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, domain.ReasonTooManyRequests, resp.StatusReason)
}

func TestCreateSBOM_Exhausted429RateLimitFromResolveSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`received status code: 429`))
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
		ImageId:         u.Host + "/test-image-resolve-429",
		ImageTag:        u.Host + "/test-image-resolve-429:latest",
		Platform:        "linux/amd64",
		MaxImageSize:    1 << 30,
		MaxSbomSize:     1 << 30,
		TimeoutSeconds:  5,
		InsecureUseHttp: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, domain.ReasonTooManyRequests, resp.StatusReason)
}
