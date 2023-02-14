package tools

import (
	"testing"

	"gotest.tools/v3/assert"
)

func EnsureSetup(t *testing.T, errored bool) {
	assert.Assert(t, errored, "Error during test setup")
}
