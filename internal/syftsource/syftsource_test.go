package syftsource

import (
	"errors"
	"fmt"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePlatform(t *testing.T) {
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
			got, err := ParsePlatform(tt.platform)
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

func TestGetSourceConfig_usesPlatform(t *testing.T) {
	platform, err := ParsePlatform("linux/arm64")
	require.NoError(t, err)

	cfg := GetSourceConfig(&image.RegistryOptions{}, platform)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.SourceProviderConfig)
	require.NotNil(t, cfg.SourceProviderConfig.Platform)
	assert.Equal(t, "linux", cfg.SourceProviderConfig.Platform.OS)
	assert.Equal(t, "arm64", cfg.SourceProviderConfig.Platform.Architecture)
}

// The point of the package: both SBOM paths resolve a platform the same way, so an
// architecture on its own means the same thing whichever one runs it.
func TestGetSourceConfig_restrictsToRegistry(t *testing.T) {
	cfg := GetSourceConfig(&image.RegistryOptions{}, nil)
	require.NotNil(t, cfg)
	assert.Equal(t, []string{"registry"}, cfg.Sources,
		"kubevuln always pulls; falling back to a local daemon or containerd socket is not wanted")
}

// TestIsPlatformMismatch pins what counts as a platform mismatch for both SBOM paths.
// The "unrelated error" case is the one that matters: classification is by typed error,
// so an error that merely mentions the phrase must not be treated as one.
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
			assert.Equal(t, tt.want, IsPlatformMismatch(tt.err))
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
		{name: "os known, arch unknown", os: "linux", want: ""},
		{name: "variant without arch", variant: "v7", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FormatResolvedPlatform(tt.os, tt.arch, tt.variant))
		})
	}
}
