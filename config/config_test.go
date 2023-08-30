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
	services, err := LoadBackendServicesConfig("testdata")
	assert.NoError(t, err)
	assert.Equal(t, "https://api.armosec.io", services.GetApiServerUrl())
}
