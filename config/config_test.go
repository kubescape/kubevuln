package config

import (
	"testing"

	"github.com/spf13/viper"
	"gotest.tools/v3/assert"
)

func TestLoadConfig(t *testing.T) {
	viper.Reset()
	_, err := LoadConfig("testdata")
	assert.Assert(t, err == nil)
}

func TestLoadConfigNotFound(t *testing.T) {
	viper.Reset()
	_, err := LoadConfig("testdataInvalid")
	assert.Assert(t, err != nil)
}
