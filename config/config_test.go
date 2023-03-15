package config

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestLoadConfig(t *testing.T) {
	_, err := LoadConfig("testdata")
	assert.Assert(t, err == nil)
}
