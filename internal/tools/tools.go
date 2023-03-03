package tools

import (
	"runtime/debug"
	"testing"

	"gotest.tools/v3/assert"
)

func EnsureSetup(t *testing.T, errored bool) {
	assert.Assert(t, errored, "Error during test setup")
}

func PackageVersion(name string) string {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range bi.Deps {
			if dep.Path == name {
				return dep.Version
			}
		}
	}
	return "unknown"
}
