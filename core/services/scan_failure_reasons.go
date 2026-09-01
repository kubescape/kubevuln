package services

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	sbomscanner "github.com/kubescape/kubevuln/pkg/sbomscanner/v1"
)

// classifySBOMError inspects the error returned by CreateSBOM and returns
// a reason code constant. Uses errors.Is for sentinel errors (Go 1.13+),
// errors.As for typed errors, and falls back to string matching.
func classifySBOMError(err error) string {
	if err == nil {
		return scanfailure.ReasonUnexpected
	}

	// Sidecar-specific: scanner process crashed (OOM, SIGKILL)
	if errors.Is(err, sbomscanner.ErrScannerCrashed) {
		return scanfailure.ReasonScannerOOMKilled
	}
	if errors.Is(err, sbomscanner.ErrScannerUnavailable) {
		return scanfailure.ReasonSBOMGenerationFailed
	}

	// Context deadline exceeded → scan timeout
	if errors.Is(err, context.DeadlineExceeded) {
		return scanfailure.ReasonScanTimeout
	}

	// Go 1.13 pattern: typed error extraction via errors.As
	var transportErr *transport.Error
	if errors.As(err, &transportErr) {
		switch {
		case transportErr.StatusCode == http.StatusUnauthorized ||
			transportErr.StatusCode == http.StatusForbidden:
			return scanfailure.ReasonImageAuthFailed
		case transportErr.StatusCode == http.StatusNotFound:
			return scanfailure.ReasonImageNotFound
		}
	}

	// Requested platform doesn't exist in the image's manifest. In-process adapter calls
	// preserve the typed error; sidecar calls lose it crossing gRPC (ErrorMessage is a plain
	// string), hence the string fallback below. armoapi-go has no dedicated "platform not
	// found" reason code (see #512) — ReasonImageNotFound is the closest existing match: the
	// manifest for the requested platform variant is, in effect, not there.
	var platformErr *image.ErrPlatformMismatch
	if errors.As(err, &platformErr) {
		return scanfailure.ReasonImageNotFound
	}

	// String-based fallbacks for errors not using typed wrapping
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "401 Unauthorized") || strings.Contains(errStr, "403 Forbidden"):
		return scanfailure.ReasonImageAuthFailed
	case strings.Contains(errStr, "UNAUTHORIZED"):
		// uppercase code, same rationale as MANIFEST_UNKNOWN below: stable across registries
		// even when the typed *transport.Error doesn't survive (e.g. crossing gRPC to the sidecar).
		return scanfailure.ReasonImageAuthFailed
	case strings.Contains(errStr, "404 Not Found") ||
		strings.Contains(errStr, "MANIFEST_UNKNOWN") ||
		strings.Contains(errStr, "NAME_UNKNOWN") ||
		strings.Contains(errStr, "BLOB_UNKNOWN"):
		// NAME_UNKNOWN: repository does not exist (distinct from MANIFEST_UNKNOWN: unknown
		// tag/digest on an existing repo). Same "not found" bucket since armoapi-go has no
		// dedicated reason.
		return scanfailure.ReasonImageNotFound
	// uppercase code is the stable token; lowercase phrase varies by registry. A typed
	// *transport.Error (HTTP 400 + code) also lands here, as its Error() includes the code.
	case strings.Contains(errStr, "MANIFEST_SCHEMA_UNSUPPORTED") ||
		strings.Contains(errStr, "unsupported schema manifest"):
		return scanfailure.ReasonImageSchemaUnsupported
	case strings.Contains(errStr, "mismatched platform"):
		// (*image.ErrPlatformMismatch).Error() text, surfaced as-is by the sidecar path's
		// generic ErrorMessage fallback (pkg/sbomscanner/v1/server.go's isPlatformMismatch case).
		return scanfailure.ReasonImageNotFound
	}

	return scanfailure.ReasonSBOMGenerationFailed
}

// classifySBOMStatus maps a non-error SBOM status to a reason code.
// Called when CreateSBOM returns nil error but sets a degraded status.
// The Syft adapter masks timeout and image-too-large as nil error + status.
// The sidecar adapter marks crash-exhausted images as TooLarge with a
// memory-limit annotation — classifySBOMStatusWithAnnotation handles that case.
func classifySBOMStatus(status string) string {
	switch status {
	case helpersv1.TooLarge:
		return scanfailure.ReasonImageTooLarge
	case helpersv1.Incomplete:
		return scanfailure.ReasonSBOMIncomplete
	default:
		return scanfailure.ReasonSBOMGenerationFailed
	}
}

// classifySBOMStatusWithAnnotation refines classification using SBOM annotations.
// When the sidecar exhausts crash retries, it sets TooLarge + "scanner OOM" annotation.
func classifySBOMStatusWithAnnotation(status string, annotations map[string]string) string {
	if status == helpersv1.TooLarge {
		if ann, ok := annotations[domain.StatusReasonAnnotationKey]; ok {
			switch ann {
			case domain.ReasonImageTooLarge:
				return scanfailure.ReasonImageTooLarge
			case domain.ReasonSBOMTooLarge:
				return scanfailure.ReasonSBOMTooLarge
			case domain.ReasonScannerOOM:
				return scanfailure.ReasonScannerOOMKilled
			}
		}
		// Fallback for older OOM-marked SBOMs
		if ann, ok := annotations[helpersv1.StatusMetadataKey]; ok && strings.Contains(ann, "scanner OOM") {
			return scanfailure.ReasonScannerOOMKilled
		}
	}
	return classifySBOMStatus(status)
}
