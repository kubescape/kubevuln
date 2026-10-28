package syftsource

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlatformSlugSuffix(t *testing.T) {
	for specifier, want := range map[string]string{
		"":               "",
		"linux/amd64":    "-linux-amd64",
		"linux/arm64":    "-linux-arm64",
		"linux/arm64/v8": "-linux-arm64",
		"arm64":          "-linux-arm64",
		"Windows/AMD64":  "-windows-amd64",
		"linux/arm/v7":   "-linux-arm-v7",
	} {
		got, err := PlatformSlugSuffix(specifier)
		require.NoError(t, err, specifier)
		assert.Equal(t, want, got, specifier)
	}
	for _, specifier := range []string{"linux:amd64", "linux/arm/" + strings.Repeat("v", 300)} {
		_, err := PlatformSlugSuffix(specifier)
		assert.Error(t, err, specifier)
	}
}
