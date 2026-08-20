package v1

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/gofrs/flock"
	"github.com/kinbiko/jsonassert"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fileContent(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func Test_syftAdapter_Version(t *testing.T) {
	s := NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024, false, nil)
	version := s.Version()
	assert.NotEqual(t, version, "")
}

func Test_syftAdapter_transformations(t *testing.T) {
	// Load from file
	b := fileContent("testdata/alpine-sbom.json")

	// Convert to model.Document
	var d model.Document
	err := json.Unmarshal(b, &d)
	require.NoError(t, err)

	// Convert to syft.sbom
	sbom := toSyftModel(d)

	// Convert to domain.sbom
	s := NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024, false, nil)
	domainSBOM, err := s.syftToDomain(*sbom)
	require.NoError(t, err)

	// compare file with domain.sbom
	ja := jsonassert.New(t)
	b2, err := json.Marshal(domainSBOM)
	require.NoError(t, err)
	ja.Assert(string(b2), string(b))
}

func TestNormalizeImageID(t *testing.T) {
	tests := []struct {
		name     string
		imageID  string
		imageTag string
		want     string
	}{
		{
			name:     "replicaset-kubevuln-666dbffc4f-kubevuln-ca1b-6f47",
			imageID:  "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageTag: "quay.io/kubescape/kubevuln:v0.3.2",
			want:     "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:     "trap",
			imageID:  "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageTag: "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:     "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:     "trap 2",
			imageID:  "@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageTag: "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:     "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:     "trap 3",
			imageID:  "titi@toto@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageTag: "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:     "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:     "quay.io-kubescape-kubescape-v3.0.3-88a469",
			imageID:  "86413975e2d0330176894e4f3f5987505ed27b1191f2537797fbbf345b88a469",
			imageTag: "quay.io/kubescape/kubescape:v3.0.3",
			want:     "quay.io/kubescape/kubescape@sha256:86413975e2d0330176894e4f3f5987505ed27b1191f2537797fbbf345b88a469",
		},
		{
			name:     "registry.k8s.io-kube-scheduler-v1.28.4-3d2c54",
			imageID:  "sha256:05c284c929889d88306fdb3dd14ee2d0132543740f9e247685243214fc3d2c54",
			imageTag: "registry.k8s.io/kube-scheduler:v1.28.4",
			want:     "registry.k8s.io/kube-scheduler@sha256:05c284c929889d88306fdb3dd14ee2d0132543740f9e247685243214fc3d2c54",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NormalizeImageID(tt.imageID, tt.imageTag), "normalizeImageID(%v, %v)", tt.imageID, tt.imageTag)
		})
	}
}

func TestRewriteImageRef(t *testing.T) {
	tests := []struct {
		name     string
		imageRef string
		proxyMap map[string]string
		want     string
	}{
		{
			name:     "nil map returns original",
			imageRef: "docker.io/library/nginx:latest",
			proxyMap: nil,
			want:     "docker.io/library/nginx:latest",
		},
		{
			name:     "empty map returns original",
			imageRef: "docker.io/library/nginx:latest",
			proxyMap: map[string]string{},
			want:     "docker.io/library/nginx:latest",
		},
		{
			name:     "empty proxy value is skipped, returns original",
			imageRef: "docker.io/library/nginx:latest",
			proxyMap: map[string]string{"docker.io": ""},
			want:     "docker.io/library/nginx:latest",
		},
		{
			name:     "trailing slash in proxy value is stripped",
			imageRef: "docker.io/library/nginx:latest",
			proxyMap: map[string]string{"docker.io": "mirror.io/"},
			want:     "mirror.io/library/nginx:latest",
		},
		{
			name:     "basic rewrite",
			imageRef: "docker.io/library/alpine:3.18",
			proxyMap: map[string]string{"docker.io": "mirror.example.com"},
			want:     "mirror.example.com/library/alpine:3.18",
		},
		{
			name:     "index.docker.io in ref matched by docker.io key",
			imageRef: "index.docker.io/library/alpine:latest",
			proxyMap: map[string]string{"docker.io": "mirror.example.com"},
			want:     "mirror.example.com/library/alpine:latest",
		},
		{
			name:     "docker.io in ref matched by index.docker.io key",
			imageRef: "docker.io/library/alpine:latest",
			proxyMap: map[string]string{"index.docker.io": "mirror.example.com"},
			want:     "mirror.example.com/library/alpine:latest",
		},
		{
			name:     "digest ref is rewritten",
			imageRef: "docker.io/library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			proxyMap: map[string]string{"docker.io": "mirror.example.com"},
			want:     "mirror.example.com/library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
		},
		{
			name:     "non-matching prefix returns original",
			imageRef: "quay.io/kubescape/kubevuln:latest",
			proxyMap: map[string]string{"docker.io": "mirror.example.com"},
			want:     "quay.io/kubescape/kubevuln:latest",
		},
		{
			name:     "longest prefix wins over shorter prefix",
			imageRef: "docker.io/library/nginx:latest",
			proxyMap: map[string]string{
				"docker.io":         "generic-mirror.example.com",
				"docker.io/library": "library-mirror.example.com",
			},
			want: "library-mirror.example.com/nginx:latest",
		},
		{
			name:     "multiple entries, correct one matches",
			imageRef: "quay.io/kubescape/kubevuln:latest",
			proxyMap: map[string]string{
				"docker.io": "mirror.example.com",
				"quay.io":   "quay-mirror.example.com",
			},
			want: "quay-mirror.example.com/kubescape/kubevuln:latest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rewriteImageRef(tt.imageRef, tt.proxyMap))
		})
	}
}

func Test_syftAdapter_CreateSBOM_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	adapter := NewSyftAdapter(10*time.Second, 100*1024*1024, 10*1024*1024, false, nil)
	_, err := adapter.CreateSBOM(ctx, "test", "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501", "library/alpine:latest", domain.RegistryOptions{})

	require.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled"))
}

func Test_syftAdapter_CreateSBOM_TimeoutContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	<-ctx.Done() // wait for context deadline

	adapter := NewSyftAdapter(10*time.Second, 100*1024*1024, 10*1024*1024, false, nil)
	sbom, err := adapter.CreateSBOM(ctx, "test", "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501", "library/alpine:latest", domain.RegistryOptions{})

	assert.NoError(t, err)
	assert.Equal(t, helpersv1.Incomplete, sbom.Status)
}

// activeScanLockPathForTest must match internal/tools' own unexported activeScanLockPath(os.TempDir()):
// same directory (os.TempDir(), which BeginActiveTempDirUse is always called with here and in
// pkg/sbomscanner/v1), same filename. There is no exported way to ask tools for this path, so it
// is duplicated here deliberately, the same way #796's own evidence had to cite it as a literal
// to describe the mechanism from outside internal/tools.
func activeScanLockPathForTest() string {
	return filepath.Join(os.TempDir(), ".kubevuln-active-scan.lock")
}

// Test_syftAdapter_CreateSBOM_PullHoldsTempDirGuard is the regression test for #796:
// BeginActiveTempDirUse used to be registered only once the pull had already finished (right
// before cataloguing started), leaving the pull itself - which is what actually creates the
// stereoscope temp dir and downloads layers into it - completely unprotected against a
// concurrent StartPeriodicTempDirSweep pass in this process or the sidecar's, sharing the same
// os.TempDir(). This stalls a real pull mid-flight (the manifest request never completes until
// released) and, while it's stalled, asserts that a fresh, independent handle on the same
// cross-process lease file cannot take the exclusive lock StartPeriodicTempDirSweep's own
// acquireSweepLease needs before it will remove anything - proving the guard is held for the
// pull, not just for cataloguing afterward.
func Test_syftAdapter_CreateSBOM_PullHoldsTempDirGuard(t *testing.T) {
	// Both this test and its sidecar counterpart (pkg/sbomscanner/v1) contend for the same
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

	adapter := NewSyftAdapter(30*time.Second, 100*1024*1024, 10*1024*1024, false, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = adapter.CreateSBOM(context.Background(), "test", "", u.Host+"/test-image:latest", domain.RegistryOptions{InsecureUseHTTP: true})
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

// mockRegistryImage serves a minimal single-layer image so syft.GetSource resolves without a
// network, letting a test reach CreateSBOM's deadline handling. Returns the registry host.
func mockRegistryImage(t *testing.T) string {
	t.Helper()

	layer := &bytes.Buffer{}
	gz := gzip.NewWriter(layer)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "etc/hostname", Mode: 0o644, Size: 4}))
	_, err := tw.Write([]byte("test"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	layerBytes := layer.Bytes()
	layerHash := fmt.Sprintf("%x", sha256.Sum256(layerBytes))

	uncompressed := &bytes.Buffer{}
	zr, err := gzip.NewReader(bytes.NewReader(layerBytes))
	require.NoError(t, err)
	_, err = io.Copy(uncompressed, zr)
	require.NoError(t, err)
	diffID := fmt.Sprintf("%x", sha256.Sum256(uncompressed.Bytes()))

	configBytes := []byte(fmt.Sprintf(
		`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}`, diffID))
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
		case "/v2/test-image/blobs/sha256:" + configHash:
			_, _ = w.Write(configBytes)
		case "/v2/test-image/blobs/sha256:" + layerHash:
			_, _ = w.Write(layerBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	return u.Host
}

// deadline.Run cannot stop its work function, and Syft's cataloguers do not observe
// cancellation, so on timeout the Syft goroutine keeps running and finishes after CreateSBOM
// has already returned Incomplete. The work function must therefore share nothing with the
// caller. Run under -race, this fails if it writes a variable the caller reads.
func Test_syftAdapter_CreateSBOM_TimeoutDoesNotRaceWithAbandonedSyft(t *testing.T) {
	host := mockRegistryImage(t)

	finished := make(chan struct{})
	orig := createSBOMFn
	defer func() { createSBOMFn = orig }()
	createSBOMFn = func(_ context.Context, _ source.Source, _ *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		time.Sleep(1500 * time.Millisecond)
		defer close(finished)
		return &sbom.SBOM{}, nil
	}

	adapter := NewSyftAdapter(1*time.Second, 1<<30, 1<<30, false, nil)
	domainSBOM, err := adapter.CreateSBOM(context.Background(), "test", "", host+"/test-image:latest", domain.RegistryOptions{InsecureUseHTTP: true})

	require.NoError(t, err)
	assert.Equal(t, helpersv1.Incomplete, domainSBOM.Status, "the deadline must surface as Incomplete")

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("stand-in Syft never finished")
	}
	assert.Equal(t, helpersv1.Incomplete, domainSBOM.Status, "the late write must not affect the result")
}

// Test_syftAdapter_CreateSBOM_SerializesWithAbandonedGoroutineAfterTimeout is a regression test
// for #687: pullMutex exists to prevent concurrent pulls/cataloging from exhausting disk, but
// was released via a defer in CreateSBOM's own return path. Since deadline.Run cannot stop the
// goroutine it spawns, a timed-out call's abandoned goroutine keeps running after CreateSBOM
// returns Incomplete - so releasing the mutex at that point let a second CreateSBOM call start
// pulling/cataloging fully concurrently with the still-running first one. This asserts the
// second call cannot reach its own cataloging step until the first call's abandoned goroutine
// has actually finished.
func Test_syftAdapter_CreateSBOM_SerializesWithAbandonedGoroutineAfterTimeout(t *testing.T) {
	host := mockRegistryImage(t)

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstAbandonedGoroutineFinished := make(chan struct{})
	secondStarted := make(chan struct{})

	orig := createSBOMFn
	defer func() { createSBOMFn = orig }()
	var calls atomic.Int32
	createSBOMFn = func(_ context.Context, _ source.Source, _ *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
			close(firstAbandonedGoroutineFinished)
			return &sbom.SBOM{}, nil
		}
		close(secondStarted)
		return &sbom.SBOM{}, nil
	}

	adapter := NewSyftAdapter(1*time.Second, 1<<30, 1<<30, false, nil)

	type createSBOMResult struct {
		domainSBOM domain.SBOM
		err        error
	}

	firstReturned := make(chan struct{})
	firstResult := make(chan createSBOMResult, 1)
	go func() {
		defer close(firstReturned)
		domainSBOM, err := adapter.CreateSBOM(context.Background(), "test", "", host+"/test-image:latest", domain.RegistryOptions{InsecureUseHTTP: true})
		firstResult <- createSBOMResult{domainSBOM, err}
	}()

	select {
	case <-firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first call's stand-in Syft never started")
	}
	select {
	case <-firstReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("first CreateSBOM call never returned once its deadline elapsed")
	}
	firstRes := <-firstResult
	require.NoError(t, firstRes.err)
	assert.Equal(t, helpersv1.Incomplete, firstRes.domainSBOM.Status)
	// CreateSBOM has returned Incomplete, but its abandoned goroutine is still blocked in
	// createSBOMFn, holding pullMutex.

	secondReturned := make(chan struct{})
	secondResult := make(chan createSBOMResult, 1)
	go func() {
		defer close(secondReturned)
		domainSBOM, err := adapter.CreateSBOM(context.Background(), "test", "", host+"/test-image:latest", domain.RegistryOptions{InsecureUseHTTP: true})
		secondResult <- createSBOMResult{domainSBOM, err}
	}()

	select {
	case <-secondStarted:
		t.Fatal("second CreateSBOM call reached cataloging while the first call's abandoned goroutine was still running")
	case <-time.After(300 * time.Millisecond):
		// expected: the second call is blocked waiting for pullMutex
	}

	close(releaseFirst)

	select {
	case <-firstAbandonedGoroutineFinished:
	case <-time.After(5 * time.Second):
		t.Fatal("first call's abandoned goroutine never finished")
	}
	select {
	case <-secondStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("second call never proceeded once the first call's abandoned goroutine released pullMutex")
	}
	select {
	case <-secondReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("second CreateSBOM call never returned")
	}
	secondRes := <-secondResult
	require.NoError(t, secondRes.err)
}

// archRegistryVariant is one platform-specific manifest+config+layer served by
// mockMultiArchRegistry below.
type archRegistryVariant struct {
	arch          string
	layerBytes    []byte
	layerHash     string
	configBytes   []byte
	configHash    string
	manifestBytes []byte
	manifestHash  string
}

func buildArchRegistryVariant(t *testing.T, arch, marker string) archRegistryVariant {
	t.Helper()

	layer := &bytes.Buffer{}
	gz := gzip.NewWriter(layer)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "etc/hostname", Mode: 0o644, Size: int64(len(marker))}))
	_, err := tw.Write([]byte(marker))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	layerBytes := layer.Bytes()
	layerHash := fmt.Sprintf("%x", sha256.Sum256(layerBytes))

	uncompressed := &bytes.Buffer{}
	zr, err := gzip.NewReader(bytes.NewReader(layerBytes))
	require.NoError(t, err)
	_, err = io.Copy(uncompressed, zr)
	require.NoError(t, err)
	diffID := fmt.Sprintf("%x", sha256.Sum256(uncompressed.Bytes()))

	configBytes := []byte(fmt.Sprintf(
		`{"architecture":%q,"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}`, arch, diffID))
	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))

	manifestBytes := []byte(fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": %d, "digest": "sha256:%s"},
		"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": %d, "digest": "sha256:%s"}]
	}`, len(configBytes), configHash, len(layerBytes), layerHash))
	manifestHash := fmt.Sprintf("%x", sha256.Sum256(manifestBytes))

	return archRegistryVariant{
		arch:          arch,
		layerBytes:    layerBytes,
		layerHash:     layerHash,
		configBytes:   configBytes,
		configHash:    configHash,
		manifestBytes: manifestBytes,
		manifestHash:  manifestHash,
	}
}

// mockMultiArchRegistry serves a Docker manifest list (fat manifest) with distinct amd64 and
// arm64 entries under the same tag, purely from local fixtures. It lets platform-resolution
// tests assert deterministic behavior on both architectures without depending on the host's
// runtime.GOARCH or reaching a real registry. Returns the registry host.
func mockMultiArchRegistry(t *testing.T) string {
	t.Helper()

	amd64 := buildArchRegistryVariant(t, "amd64", "amd64-marker")
	arm64 := buildArchRegistryVariant(t, "arm64", "arm64-marker")
	variantsByManifestHash := map[string]archRegistryVariant{
		amd64.manifestHash: amd64,
		arm64.manifestHash: arm64,
	}
	blobsByHash := map[string][]byte{
		amd64.configHash: amd64.configBytes,
		amd64.layerHash:  amd64.layerBytes,
		arm64.configHash: arm64.configBytes,
		arm64.layerHash:  arm64.layerBytes,
	}

	indexBytes := []byte(fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
		"manifests": [
			{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": %d, "digest": "sha256:%s", "platform": {"architecture": "amd64", "os": "linux"}},
			{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": %d, "digest": "sha256:%s", "platform": {"architecture": "arm64", "os": "linux"}}
		]
	}`, len(amd64.manifestBytes), amd64.manifestHash, len(arm64.manifestBytes), arm64.manifestHash))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/v2/test-image/manifests/latest":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.list.v2+json")
			_, _ = w.Write(indexBytes)
		case strings.HasPrefix(r.URL.Path, "/v2/test-image/manifests/sha256:"):
			digest := strings.TrimPrefix(r.URL.Path, "/v2/test-image/manifests/sha256:")
			if v, ok := variantsByManifestHash[digest]; ok {
				w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
				_, _ = w.Write(v.manifestBytes)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case strings.HasPrefix(r.URL.Path, "/v2/test-image/blobs/sha256:"):
			digest := strings.TrimPrefix(r.URL.Path, "/v2/test-image/blobs/sha256:")
			if b, ok := blobsByHash[digest]; ok {
				_, _ = w.Write(b)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	return u.Host
}

// Test_syftAdapter_CreateSBOM_MultiArchLocalRegistry is a regression test for architecture-
// dependent test behavior: with no platform requested, stereoscope's registry provider
// defaults to runtime.GOARCH (see defaultPlatformIfNil in
// github.com/anchore/stereoscope/pkg/image/oci), so a manifest-list image resolves
// differently depending on which architecture the test happens to run on. Requesting the
// platform explicitly, against a local manifest list serving both amd64 and arm64, must
// resolve the matching entry regardless of the host's own architecture.
func Test_syftAdapter_CreateSBOM_MultiArchLocalRegistry(t *testing.T) {
	host := mockMultiArchRegistry(t)

	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		t.Run(platform, func(t *testing.T) {
			adapter := NewSyftAdapter(10*time.Second, 100*1024*1024, 10*1024*1024, false, nil)
			domainSBOM, err := adapter.CreateSBOM(context.Background(), "test", "", host+"/test-image:latest",
				domain.RegistryOptions{Platform: platform, InsecureUseHTTP: true})

			require.NoError(t, err)
			assert.Equal(t, platform, domainSBOM.Annotations[domain.ResolvedPlatformAnnotationKey],
				"resolved platform must match what was requested, independent of the host's runtime.GOARCH=%s", runtime.GOARCH)
		})
	}
}

func Test_syftAdapter_CreateSBOM_Retry429RateLimit(t *testing.T) {
	var attempts int
	var mu sync.Mutex

	layer := &bytes.Buffer{}
	gz := gzip.NewWriter(layer)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "etc/hostname", Mode: 0o644, Size: 4}))
	_, err := tw.Write([]byte("test"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	layerBytes := layer.Bytes()
	layerHash := fmt.Sprintf("%x", sha256.Sum256(layerBytes))

	uncompressed := &bytes.Buffer{}
	zr, err := gzip.NewReader(bytes.NewReader(layerBytes))
	require.NoError(t, err)
	_, err = io.Copy(uncompressed, zr)
	require.NoError(t, err)
	diffID := fmt.Sprintf("%x", sha256.Sum256(uncompressed.Bytes()))

	configBytes := []byte(fmt.Sprintf(
		`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}`, diffID))
	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		if r.URL.Path == "/v2/test-image-retry/manifests/latest" {
			mu.Lock()
			attempts++
			curr := attempts
			mu.Unlock()
			if curr == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"errors":[{"code":"TOOMANYREQUESTS","message":"rate limited"}]}`))
				return
			}
		}

		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/test-image-retry/manifests/latest":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{
				"schemaVersion": 2,
				"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
				"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": %d, "digest": "sha256:%s"},
				"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": %d, "digest": "sha256:%s"}]
			}`, len(configBytes), configHash, len(layerBytes), layerHash)))
		case "/v2/test-image-retry/blobs/sha256:" + configHash:
			_, _ = w.Write(configBytes)
		case "/v2/test-image-retry/blobs/sha256:" + layerHash:
			_, _ = w.Write(layerBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	adapter := NewSyftAdapter(10*time.Second, 100*1024*1024, 10*1024*1024, false, nil)
	domainSBOM, err := adapter.CreateSBOM(context.Background(), "test", "", u.Host+"/test-image-retry:latest", domain.RegistryOptions{InsecureUseHTTP: true})

	require.NoError(t, err)
	assert.Equal(t, helpersv1.Learning, domainSBOM.Status)
	mu.Lock()
	assert.GreaterOrEqual(t, attempts, 2, "expected at least 2 manifest request attempts due to 429 retry")
	mu.Unlock()
}
