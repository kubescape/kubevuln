package v1

import (
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
)

// parseSyftPlatform normalizes a platform specifier for multi-arch image resolution.
// The specifier uses OCI format "os/arch[/variant]" (e.g. "linux/amd64"). When only an
// architecture is provided (e.g. "amd64"), "linux/" is prepended. An empty string leaves
// platform selection unset so Syft can resolve the image's default manifest. This mirrors
// pkg/sbomscanner/v1/server.go so in-process and sidecar SBOM generation resolve the same
// manifest.
func parseSyftPlatform(platformStr string) (*image.Platform, error) {
	if platformStr == "" {
		return nil, nil
	}
	if !strings.Contains(platformStr, "/") {
		platformStr = "linux/" + platformStr
	}
	return image.NewPlatform(platformStr)
}

func syftGetSourceConfig(registryOptions *image.RegistryOptions, platform *image.Platform) *syft.GetSourceConfig {
	return syft.DefaultGetSourceConfig().
		WithRegistryOptions(registryOptions).
		WithPlatform(platform).
		WithSources("registry")
}
