package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	viper.Reset()
	_, err := LoadConfig("testdata")
	assert.NoError(t, err)
}

func TestLoadConfigNotFound(t *testing.T) {
	viper.Reset()
	_, err := LoadConfig("testdataInvalid")
	assert.Error(t, err)
}

func TestLoadBackendServicesConfig(t *testing.T) {
	services, err := LoadBackendServicesConfig("testdata", "")
	assert.NoError(t, err)
	assert.Equal(t, "https://api.armosec.io", services.GetApiServerUrl())
}

func TestLoadBackendServicesConfig_FallbackToClusterData(t *testing.T) {
	t.Run("fallback when API_URL is missing", func(t *testing.T) {
		dir := t.TempDir()
		clusterData := `{
			"backendOpenAPI":"https://api.armosec.io/api",
			"eventReceiverRestURL":"https://report.armo.cloud"
		}`
		err := os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(clusterData), 0o600)
		assert.NoError(t, err)

		services, err := LoadBackendServicesConfig(dir, "")
		assert.NoError(t, err)
		assert.Equal(t, "https://api.armosec.io", services.GetApiServerUrl())
		assert.Equal(t, "https://report.armo.cloud", services.GetReportReceiverHttpUrl())
	})

	t.Run("fallback when API_URL discovery returns 404", func(t *testing.T) {
		dir := t.TempDir()
		clusterData := `{
			"backendOpenAPI":"https://api.armosec.io/api",
			"eventReceiverRestURL":"https://report.armo.cloud"
		}`
		err := os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(clusterData), 0o600)
		assert.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		services, err := LoadBackendServicesConfig(dir, server.URL)
		assert.NoError(t, err)
		assert.Equal(t, "https://api.armosec.io", services.GetApiServerUrl())
		assert.Equal(t, "https://report.armo.cloud", services.GetReportReceiverHttpUrl())
	})
}

func TestNormalizeServiceURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "spaces only", input: "   ", want: ""},
		{name: "https with path", input: "https://api.armosec.io/api", want: "https://api.armosec.io"},
		{name: "http with path", input: "http://operator:4002/api/v3/servicediscovery", want: "http://operator:4002"},
		{name: "host without scheme", input: "api.armosec.io/api", want: "https://api.armosec.io"},
		{name: "host and port without scheme", input: "operator:4002/path", want: "https://operator:4002"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeServiceURL(tt.input))
		})
	}
}

func TestLoadBackendServicesFromClusterData_Errors(t *testing.T) {
	t.Run("missing clusterData file", func(t *testing.T) {
		_, err := loadBackendServicesFromClusterData(t.TempDir())
		assert.Error(t, err)
	})

	t.Run("invalid clusterData json", func(t *testing.T) {
		dir := t.TempDir()
		err := os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte("{invalid-json"), 0o600)
		assert.NoError(t, err)

		_, err = loadBackendServicesFromClusterData(dir)
		assert.Error(t, err)
	})

	t.Run("missing required backend urls", func(t *testing.T) {
		dir := t.TempDir()
		err := os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(`{"clusterName":"test"}`), 0o600)
		assert.NoError(t, err)

		_, err = loadBackendServicesFromClusterData(dir)
		assert.Error(t, err)
	})
}

// TestLoadConfigCVEMatchingMode covers mode resolution and backward compatibility.
func TestLoadConfigCVEMatchingMode(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantMode CVEMatchingMode
		wantErr  bool
	}{
		{name: "neither set defaults to adaptive", path: "testdata", wantMode: CVEMatchingAdaptive},
		{name: "legacy true maps to off", path: "testdata_matching/legacy_true", wantMode: CVEMatchingOff},
		{name: "legacy false maps to on", path: "testdata_matching/legacy_false", wantMode: CVEMatchingOn},
		{name: "explicit mode wins over legacy", path: "testdata_matching/explicit_wins", wantMode: CVEMatchingOn},
		{name: "explicit adaptive", path: "testdata_matching/explicit_adaptive", wantMode: CVEMatchingAdaptive},
		{name: "invalid mode errors", path: "testdata_matching/invalid", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			c, err := LoadConfig(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantMode, c.CVEMatchingMode)
		})
	}
}

// TestLoadConfigCVEMatchingModeEnv verifies env-var overrides are honored and
// do not crash LoadConfig (AutomaticEnv values are not unmarshalled, so the
// resolution must read through viper's getters).
func TestLoadConfigCVEMatchingModeEnv(t *testing.T) {
	t.Run("mode via env on empty-key config", func(t *testing.T) {
		viper.Reset()
		t.Setenv("CVEMATCHINGMODE", "on")
		c, err := LoadConfig("testdata")
		assert.NoError(t, err)
		assert.Equal(t, CVEMatchingOn, c.CVEMatchingMode)
	})
	t.Run("legacy bool via env maps to off", func(t *testing.T) {
		viper.Reset()
		t.Setenv("USEDEFAULTMATCHERS", "true")
		c, err := LoadConfig("testdata")
		assert.NoError(t, err)
		assert.Equal(t, CVEMatchingOff, c.CVEMatchingMode)
	})
}

// TestLoadConfigTrustedVendors covers the trusted-vendor default and override.
func TestLoadConfigTrustedVendors(t *testing.T) {
	viper.Reset()
	c, err := LoadConfig("testdata")
	assert.NoError(t, err)
	assert.Equal(t, defaultTrustedVendors, c.TrustedVendors)

	viper.Reset()
	c, err = LoadConfig("testdata_matching/explicit_adaptive")
	assert.NoError(t, err)
	assert.Equal(t, []string{"echo", "acme"}, c.TrustedVendors)
}

// test proxyRegistryMap is loaded correctly
func TestLoadConfigProxyRegistryMap(t *testing.T) {
	viper.Reset()
	config, err := LoadConfig("testdata")
	assert.NoError(t, err)
	expected := map[string]string{
		"docker.io": "my-mirror.example.com",
		"quay.io":   "my-mirror.example.com",
		"gcr.io":    "my-mirror.example.com",
	}
	assert.Equal(t, expected, config.ProxyRegistryMap)
}
