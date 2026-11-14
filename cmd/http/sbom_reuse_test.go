package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/config"
	"github.com/stretchr/testify/require"
)

func TestConfigureSBOMReuseDisabledAndInvalid(t *testing.T) {
	fallback := adapters.NewMockSBOMAdapter(false, false, false)
	got, err := configureSBOMReuse(config.Config{}, fallback)
	require.NoError(t, err)
	require.Same(t, fallback, got)
	path := filepath.Join(t.TempDir(), "policy.json")
	_, err = configureSBOMReuse(config.Config{SBOMReusePolicyFile: path}, fallback)
	require.Error(t, err)
	require.NoError(t, os.WriteFile(path, []byte(`{"repositories":{}}`), 0600))
	_, err = configureSBOMReuse(config.Config{SBOMReusePolicyFile: path}, fallback)
	require.ErrorContains(t, err, "approved repository")
	_, err = configureSBOMReuse(config.Config{SBOMReusePolicyFile: path, NodeSbomGeneration: true}, fallback)
	require.ErrorContains(t, err, "kubevuln-owned")
	_, err = configureSBOMReuse(config.Config{SBOMReusePolicyFile: path, ProxyRegistryMap: map[string]string{"source": "mirror"}}, fallback)
	require.ErrorContains(t, err, "proxyRegistryMap")
}
