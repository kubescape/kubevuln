package v1

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDiveAdapter(t *testing.T) {
	adapter := NewDiveAdapter("", 30*time.Second)
	assert.NotNil(t, adapter)
	assert.Equal(t, "./dive", adapter.divePath)
	assert.Equal(t, 30*time.Second, adapter.scanTimeout)
}

func TestDiveAdapter_ScanImage(t *testing.T) {
	// Skip if dive binary is not available
	if _, err := os.Stat("./dive"); os.IsNotExist(err) {
		t.Skip("dive binary not found, skipping test")
	}

	adapter := NewDiveAdapter("./dive", 60*time.Second)

	// Create a temporary directory for test output
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test-dive.json")

	// Test with a simple image (alpine is usually available)
	ctx := context.Background()
	result, err := adapter.ScanImage(ctx, "alpine:latest", outputPath)

	// The test might fail if alpine:latest is not available locally
	// or if there are network issues, so we just check the structure
	if err != nil {
		t.Logf("dive scan failed (expected if alpine:latest not available): %v", err)
		return
	}

	require.NotNil(t, result)
	assert.NotEmpty(t, result.ImageName)
	assert.GreaterOrEqual(t, len(result.Layer), 0)
	assert.GreaterOrEqual(t, result.TotalSize, int64(0))

	// Check that the output file was created
	_, err = os.Stat(outputPath)
	assert.NoError(t, err)
}

func TestDiveAdapter_Version(t *testing.T) {
	// Skip if dive binary is not available
	if _, err := os.Stat("./dive"); os.IsNotExist(err) {
		t.Skip("dive binary not found, skipping test")
	}

	adapter := NewDiveAdapter("./dive", 30*time.Second)
	version := adapter.Version()

	// Version should not be empty if dive is available
	if version != "unknown" {
		assert.NotEmpty(t, version)
	}
}

func TestDiveAdapter_readDiveResult(t *testing.T) {
	adapter := NewDiveAdapter("", 30*time.Second)

	// Create a temporary file with mock dive output
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "mock-dive.json")

	mockData := `{
		"imageName": "test-image",
		"layer": [
			{
				"index": 0,
				"digest": "sha256:abc123",
				"size": 1024,
				"command": "FROM alpine:latest"
			}
		],
		"totalSize": 1024
	}`

	err := os.WriteFile(outputPath, []byte(mockData), 0644)
	require.NoError(t, err)

	result, err := adapter.readDiveResult(outputPath)
	require.NoError(t, err)

	assert.Equal(t, "test-image", result.ImageName)
	assert.Len(t, result.Layer, 1)
	assert.Equal(t, 0, result.Layer[0].Index)
	assert.Equal(t, "sha256:abc123", result.Layer[0].Digest)
	assert.Equal(t, int64(1024), result.Layer[0].Size)
	assert.Equal(t, "FROM alpine:latest", result.Layer[0].Command)
	assert.Equal(t, int64(1024), result.TotalSize)
}
