package config

import (
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
