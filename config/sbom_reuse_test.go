package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSBOMReuseConfigIsOptIn(t *testing.T) {
	c, err := LoadConfig("testdata")
	require.NoError(t, err)
	require.Empty(t, c.SBOMReusePolicyFile)
	t.Setenv("SBOMREUSEPOLICYFILE", "/policy/sbom.json")
	c, err = LoadConfig("testdata")
	require.NoError(t, err)
	require.Equal(t, "/policy/sbom.json", c.SBOMReusePolicyFile)
}
