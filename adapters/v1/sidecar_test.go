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

func TestSidecarSBOMAdapter_Version(t *testing.T) {
	mock := &mockScannerClient{
		healthVersion: "v0.100.0",
		healthReady:   true,
	}

	adapter := NewSidecarSBOMAdapter(mock, 5*time.Minute, 512*1024*1024, 20*1024*1024, false, "5Gi", nil)
	assert.Equal(t, "v0.100.0", adapter.Version())
}
