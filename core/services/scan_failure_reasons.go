package services

import (
	"errors"
	"net/http"
	"strings"

	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
)

// classifySBOMError inspects the error returned by CreateSBOM and returns
// a human-friendly reason constant. Uses errors.As for typed errors (Go 1.13+)
// and falls back to string matching for errors that don't use typed wrapping.
func classifySBOMError(err error) string {
	if err == nil {
		return scanfailure.ReasonUnexpected
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
	case strings.Contains(errStr, "401 Unauthorized"):
		return scanfailure.ReasonImageAuthFailed
	case strings.Contains(errStr, "MANIFEST_UNKNOWN"):
		return scanfailure.ReasonImageNotFound
	}

	return scanfailure.ReasonSBOMGenerationFailed
}

// classifySBOMStatus maps a non-error SBOM status to a human-friendly reason.
// Called when CreateSBOM returns nil error but sets a degraded status
// (the Syft adapter masks timeout and image-too-large as nil error + status).
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
