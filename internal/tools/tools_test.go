package tools

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestEnsureSetup(t *testing.T) {
	EnsureSetup(t, true)
}

func TestPackageVersion(t *testing.T) {
	assert.Assert(t, PackageVersion("github.com/anchore/syft") == "unknown") // only works on compiled binaries
}
