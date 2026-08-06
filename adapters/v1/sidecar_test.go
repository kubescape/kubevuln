package v1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
)

// mockScannerClient implements sbomscanner.SBOMScannerClient for testing
type mockScannerClient struct {
	createSBOMFunc func(ctx context.Context, req sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error)
	healthFunc     func(ctx context.Context) (string, bool, error)
	healthVersion  string
	healthReady    bool
	healthErr      error
}

func (m *mockScannerClient) CreateSBOM(ctx context.Context, req sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
	if m.createSBOMFunc != nil {
		return m.createSBOMFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockScannerClient) Health(ctx context.Context) (string, bool, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return m.healthVersion, m.healthReady, m.healthErr
}

func (m *mockScannerClient) Ready() bool {
	return m.healthReady
}

func (m *mockScannerClient) Close() error {
	return nil
}

func TestSidecarSBOMAdapter_CreateSBOM_Success(t *testing.T) {
	mock := &mockScannerClient{
		healthVersion: "v0.100.0",
		healthReady:   true,
		createSBOMFunc: func(ctx context.Context, req sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
			return &sbomscanner.ScanResult{
				SyftDocument: &v1beta1.SyftDocument{
					Artifacts: []v1beta1.SyftPackage{
						{PackageBasicData: v1beta1.PackageBasicData{Name: "test-pkg", Version: "1.0.0"}},
					},
				},
				SBOMSize: 1024,
				Status:   helpersv1.Learning,
			}, nil
		},
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)

	sbom, err := adapter.CreateSBOM(context.Background(), "test-sbom", "", "nginx:latest", domain.RegistryOptions{})
	require.NoError(t, err)
	assert.Equal(t, helpersv1.Learning, sbom.Status)
	assert.NotNil(t, sbom.Content)
	assert.Len(t, sbom.Content.Artifacts, 1)
	assert.Equal(t, "test-pkg", sbom.Content.Artifacts[0].Name)
}

func TestSidecarSBOMAdapter_CreateSBOM_TooLarge(t *testing.T) {
	mock := &mockScannerClient{
		healthVersion: "v0.100.0",
		healthReady:   true,
		createSBOMFunc: func(ctx context.Context, req sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
			return &sbomscanner.ScanResult{
				SBOMSize: 999999999,
				Status:   helpersv1.TooLarge,
			}, nil
		},
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)

	sbom, err := adapter.CreateSBOM(context.Background(), "test-sbom", "", "large-image:latest", domain.RegistryOptions{})
	require.NoError(t, err)
	assert.Equal(t, helpersv1.TooLarge, sbom.Status)
	assert.Nil(t, sbom.Content)
}

// TestSidecarSBOMAdapter_CreateSBOM_TooManyRequests is a regression test: the sidecar
// scanner reports a registry 429 as a plain StatusReason string over gRPC (see
// pkg/sbomscanner/v1/server.go). The adapter must wrap the domain.ErrTooManyRequests
// sentinel around that so ScanService.checkCreateSBOM's errors.Is(...) check recognizes it
// and records the image as rate limited, exactly as it already does for the in-process
// syft adapter's pull errors.
func TestSidecarSBOMAdapter_CreateSBOM_TooManyRequests(t *testing.T) {
	mock := &mockScannerClient{
		healthVersion: "v0.100.0",
		healthReady:   true,
		createSBOMFunc: func(ctx context.Context, req sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
			return &sbomscanner.ScanResult{
				ErrorMessage: "received status code: 429",
				StatusReason: domain.ReasonTooManyRequests,
			}, nil
		},
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)

	_, err := adapter.CreateSBOM(context.Background(), "test-sbom", "", "rate-limited-image:latest", domain.RegistryOptions{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, domain.ErrTooManyRequests), "expected domain.ErrTooManyRequests to be recoverable via errors.Is, got: %v", err)
}

func TestSidecarSBOMAdapter_CreateSBOM_CrashRetry(t *testing.T) {
	callCount := 0
	mock := &mockScannerClient{
		healthVersion: "v0.100.0",
		healthReady:   true,
		createSBOMFunc: func(ctx context.Context, req sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
			callCount++
			return nil, sbomscanner.ErrScannerCrashed
		},
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)

	// First two attempts should return crash error (for retry)
	for i := 0; i < 2; i++ {
		_, err := adapter.CreateSBOM(context.Background(), "test-sbom", "", "crash-image:latest", domain.RegistryOptions{})
		require.Error(t, err)
		assert.ErrorIs(t, err, sbomscanner.ErrScannerCrashed)
	}

	// Third attempt should mark as TooLarge (exhausted retries)
	sbom, err := adapter.CreateSBOM(context.Background(), "test-sbom", "", "crash-image:latest", domain.RegistryOptions{})
	require.NoError(t, err)
	assert.Equal(t, helpersv1.TooLarge, sbom.Status)
	assert.Equal(t, 3, callCount)
}

// TestSidecarSBOMAdapter_CreateSBOM_EmptyDigestSendsTag is the regression guard for
// the double-normalization bug. A registry scan arrives with an empty image digest
// (imageID == "") and only a tag. The adapter is the single normalization point, so
// it must send the tag as-is to the scanner — ImageID == ImageTag == the tag — and
// must NOT graft the tag into a fake digest like repo@sha256:<tag>.
func TestSidecarSBOMAdapter_CreateSBOM_EmptyDigestSendsTag(t *testing.T) {
	const imageTag = "quay.io/systemtests/webgoat:latest"

	var got sbomscanner.ScanRequest
	mock := &mockScannerClient{
		healthVersion: "v0.100.0",
		healthReady:   true,
		createSBOMFunc: func(_ context.Context, req sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
			got = req
			return &sbomscanner.ScanResult{Status: helpersv1.Learning}, nil
		},
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)

	_, err := adapter.CreateSBOM(context.Background(), "test-sbom", "", imageTag, domain.RegistryOptions{})
	require.NoError(t, err)

	assert.Equal(t, imageTag, got.ImageID, "empty digest must scan by tag, not be grafted into a digest")
	assert.Equal(t, imageTag, got.ImageTag)
	assert.Equal(t, got.ImageTag, got.ImageID, "ImageID and ImageTag must match for an empty-digest registry scan")
}

func TestSidecarSBOMAdapter_Version(t *testing.T) {
	mock := &mockScannerClient{
		healthVersion: "v0.100.0",
		healthReady:   true,
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)
	assert.Equal(t, "v0.100.0", adapter.Version())
}

// TestSidecarSBOMAdapter_Version_RecoversAfterTransientFailure is a regression test for
// #473: Version() used to cache its result behind a sync.Once, so a single failed/timed-out
// Health() call (e.g. a cold-start blip) permanently pinned every later call to "unknown" for
// the adapter's lifetime — corrupting the SBOM/CVE storage cache key. Version() must retry on
// the next call after a failure and only cache once Health() actually succeeds.
func TestSidecarSBOMAdapter_Version_RecoversAfterTransientFailure(t *testing.T) {
	callCount := 0
	mock := &mockScannerClient{
		healthFunc: func(ctx context.Context) (string, bool, error) {
			callCount++
			if callCount == 1 {
				return "", false, errors.New("transient health check failure")
			}
			return "v0.100.0", true, nil
		},
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)

	assert.Equal(t, "unknown", adapter.Version(), "first call hits the transient failure")
	assert.Equal(t, "v0.100.0", adapter.Version(), "second call must retry, not replay the cached failure")
	assert.Equal(t, "v0.100.0", adapter.Version(), "once resolved, the real version stays cached")
	assert.Equal(t, 2, callCount, "a resolved version must not trigger further Health() calls")
}

// TestSidecarSBOMAdapter_CreateSBOM_CrashRetry_EvictsStaleEntries is a regression test for
// #473: retryCount entries were only ever cleared on success or once maxCrashRetries was hit,
// so an image that crashed once and was never retried left a permanent entry, growing the map
// unboundedly over the adapter's lifetime (common with CI-generated unique tags/digests).
func TestSidecarSBOMAdapter_CreateSBOM_CrashRetry_EvictsStaleEntries(t *testing.T) {
	mock := &mockScannerClient{
		healthVersion: "v0.100.0",
		healthReady:   true,
		createSBOMFunc: func(ctx context.Context, req sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
			return nil, sbomscanner.ErrScannerCrashed
		},
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)

	// A one-off crash for an image that is never retried.
	_, err := adapter.CreateSBOM(context.Background(), "test-sbom", "", "one-shot-image:latest", domain.RegistryOptions{})
	require.Error(t, err)
	require.Len(t, adapter.retryCount, 1)

	// Simulate that entry going stale.
	adapter.mu.Lock()
	adapter.retryCount["one-shot-image:latest"].lastSeen = time.Now().Add(-retryCountTTL - time.Minute)
	adapter.mu.Unlock()

	// A crash for a different image should sweep the stale entry out while recording its own.
	_, err = adapter.CreateSBOM(context.Background(), "test-sbom", "", "another-image:latest", domain.RegistryOptions{})
	require.Error(t, err)

	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	assert.NotContains(t, adapter.retryCount, "one-shot-image:latest", "stale entry must be evicted")
	assert.Contains(t, adapter.retryCount, "another-image:latest")
}
