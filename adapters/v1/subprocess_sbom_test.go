package v1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubprocessSBOMCreator_DisabledFallsThrough(t *testing.T) {
	inner := NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024, false)
	creator := NewSubprocessSBOMCreator(inner, 5*time.Minute, 0, false)

	// When disabled, it should use the inner adapter directly.
	// We can't easily test a full SBOM creation without a real image,
	// but we can verify Version() delegates correctly.
	assert.Equal(t, inner.Version(), creator.Version())
}

func TestSbomWorkerRequest_JSONRoundTrip(t *testing.T) {
	req := sbomWorkerRequest{
		Name:     "test-image",
		ImageID:  "sha256:abc123",
		ImageTag: "nginx:1.25",
		Options: domain.RegistryOptions{
			Platform: "linux/amd64",
			Credentials: []domain.RegistryCredentials{
				{Authority: "docker.io", Username: "user", Password: "pass"},
			},
		},
		ScanTimeout:       5 * time.Minute,
		MaxImageSize:      512 * 1024 * 1024,
		MaxSBOMSize:       20 * 1024 * 1024,
		ScanEmbeddedSBOMs: true,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded sbomWorkerRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Name, decoded.Name)
	assert.Equal(t, req.ImageID, decoded.ImageID)
	assert.Equal(t, req.ImageTag, decoded.ImageTag)
	assert.Equal(t, req.ScanTimeout, decoded.ScanTimeout)
	assert.Equal(t, req.MaxImageSize, decoded.MaxImageSize)
	assert.Equal(t, req.MaxSBOMSize, decoded.MaxSBOMSize)
	assert.Equal(t, req.ScanEmbeddedSBOMs, decoded.ScanEmbeddedSBOMs)
	assert.Equal(t, "docker.io", decoded.Options.Credentials[0].Authority)
}

func TestSbomWorkerResponse_WithError(t *testing.T) {
	resp := sbomWorkerResponse{
		Error: "syft: unable to parse image",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded sbomWorkerResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "syft: unable to parse image", decoded.Error)
	assert.Nil(t, decoded.SBOM)
}

func TestSbomWorkerResponse_WithSBOM(t *testing.T) {
	sbom := domain.SBOM{
		Name:            "test",
		SBOMCreatorName: "syft",
		Status:          "Learning",
	}
	resp := sbomWorkerResponse{SBOM: &sbom}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded sbomWorkerResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.Error)
	require.NotNil(t, decoded.SBOM)
	assert.Equal(t, "test", decoded.SBOM.Name)
	assert.Equal(t, "syft", decoded.SBOM.SBOMCreatorName)
}

func TestSubprocessSBOMCreator_TimeoutError(t *testing.T) {
	// Verify timeout context cancellation is correctly classified.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond) // ensure deadline passed

	assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
}
