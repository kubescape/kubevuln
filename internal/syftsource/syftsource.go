// Package syftsource holds the two pieces of Syft source setup that both SBOM paths need:
// the in-process adapter in adapters/v1 and the sidecar scanner in pkg/sbomscanner/v1.
//
// They were written out separately in each, with a comment in both pointing at the other
// saying it mirrors it. Platform resolution in particular is what #512 was about, so the
// two agreeing is the property that matters, and a shared function is a stronger way to
// hold it than two copies and a note.
package syftsource

import (
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
)

// ParsePlatform normalizes a platform specifier for multi-arch image resolution. The
// specifier uses OCI format, "os/arch[/variant]" such as "linux/amd64", and an
// architecture on its own is read as Linux.
//
// An empty specifier gives a nil platform, which leaves selection unset so Syft resolves
// whatever the image manifest provides. That matters on the pod-less scan paths, registry
// rescans and periodic CRD-based rescans, which have no node context to derive a platform
// from: defaulting to the scanning process's own architecture there forced a platform
// mismatch for single-arch images that did not happen to match it (#512).
func ParsePlatform(specifier string) (*image.Platform, error) {
	if specifier == "" {
		return nil, nil
	}
	if !strings.Contains(specifier, "/") {
		specifier = "linux/" + specifier
	}
	return image.NewPlatform(specifier)
}

// GetSourceConfig builds the config both paths hand to syft.GetSource. "registry" is the
// only source: kubevuln always pulls, and leaving the default set would let Syft fall back
// to reading a local docker daemon or containerd socket that is not there.
func GetSourceConfig(registryOptions *image.RegistryOptions, platform *image.Platform) *syft.GetSourceConfig {
	return syft.DefaultGetSourceConfig().
		WithRegistryOptions(registryOptions).
		WithPlatform(platform).
		WithSources("registry")
}
