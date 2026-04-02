package services

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
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
		}
	}

	// String-based fallbacks for errors not using typed wrapping
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "401 Unauthorized") || strings.Contains(errStr, "403 Forbidden"):
		return scanfailure.ReasonImageAuthFailed
	case strings.Contains(errStr, "MANIFEST_UNKNOWN"):
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
		return scanfailure.ReasonSBOMTooLarge
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
		if ann, ok := annotations[helpersv1.StatusMetadataKey]; ok && strings.Contains(ann, "scanner OOM") {
			return scanfailure.ReasonScannerOOMKilled
		}
	}
	return classifySBOMStatus(status)
}
