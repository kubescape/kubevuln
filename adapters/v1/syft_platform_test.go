package v1

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSyftPlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		wantNil  bool
		wantOS   string
		wantArch string
		wantErr  bool
	}{
		{
			name:     "empty leaves platform unset",
			platform: "",
			wantNil:  true,
		},
		{
			name:     "architecture only gets linux prefix",
			platform: "arm64",
			wantOS:   "linux",
			wantArch: "arm64",
		},
		{
			name:     "full OCI platform is preserved",
			platform: "linux/amd64",
			wantOS:   "linux",
			wantArch: "amd64",
		},
		{
			name:     "platform with variant",
			platform: "linux/arm64/v8",
			wantOS:   "linux",
			wantArch: "arm64",
		},
		{
			name:     "invalid platform is rejected",
			platform: "not-a-valid-platform-spec",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSyftPlatform(tt.platform)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantOS, got.OS)
			assert.Equal(t, tt.wantArch, got.Architecture)
		})
	}
}

func TestSyftGetSourceConfig_usesPlatform(t *testing.T) {
	platform, err := parseSyftPlatform("linux/arm64")
	require.NoError(t, err)

	cfg := syftGetSourceConfig(&image.RegistryOptions{}, platform)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.SourceProviderConfig)
	require.NotNil(t, cfg.SourceProviderConfig.Platform)
	assert.Equal(t, "linux", cfg.SourceProviderConfig.Platform.OS)
	assert.Equal(t, "arm64", cfg.SourceProviderConfig.Platform.Architecture)
}
