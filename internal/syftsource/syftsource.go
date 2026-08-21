// Package syftsource holds the pieces of Syft source setup and platform handling that both
// SBOM paths need: the in-process adapter in adapters/v1 and the sidecar scanner in
// pkg/sbomscanner/v1.
//
// They were written out separately in each, with a comment in both pointing at the other
// saying it mirrors it. Platform resolution in particular is what #512 was about, so the
// two agreeing is the property that matters, and a shared function is a stronger way to
// hold it than two copies and a note.
package syftsource

import (
	"errors"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
)

// FormatResolvedPlatform builds an OCI-style "os/arch[/variant]" string from the platform
// fields Syft/stereoscope actually resolved an image against, so a silently-wrong-arch SBOM
// is inspectable after the fact (#512). Returns "" unless both os and architecture are
// known, since a half-known platform is not a platform.
func FormatResolvedPlatform(os, arch, variant string) string {
	if os == "" || arch == "" {
		return ""
	}
	parts := []string{os, arch}
	if variant != "" {
		parts = append(parts, variant)
	}
	return strings.Join(parts, "/")
}

// IsPlatformMismatch reports whether err is, or wraps, stereoscope's
// *image.ErrPlatformMismatch: the error raised once an image has been positively
// resolved but its OS/arch do not match the requested platform.
//
// Both SBOM paths classify this error, and both must agree on what counts as one, for the
// same reason ParsePlatform is shared: #512 was about the two paths disagreeing on
// platform handling. Matching on the typed error rather than on message text is what keeps
// an unrelated error that merely mentions "mismatched platform" from being classified as
// a platform failure.
func IsPlatformMismatch(err error) bool {
	var platformErr *image.ErrPlatformMismatch
	return errors.As(err, &platformErr)
}

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
