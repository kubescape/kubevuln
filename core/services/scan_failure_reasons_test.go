package services

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/stretchr/testify/assert"
)

func TestClassifySBOMError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "nil error returns unexpected",
			err:      nil,
			expected: scanfailure.ReasonUnexpected,
		},
		{
			name: "transport 401 via errors.As",
			err: &transport.Error{
				StatusCode: http.StatusUnauthorized,
			},
			expected: scanfailure.ReasonImageAuthFailed,
		},
		{
			name: "transport 403 via errors.As",
			err: &transport.Error{
				StatusCode: http.StatusForbidden,
			},
			expected: scanfailure.ReasonImageAuthFailed,
		},
		{
			name: "wrapped transport 401",
			err: fmt.Errorf("pulling image: %w", &transport.Error{
				StatusCode: http.StatusUnauthorized,
			}),
			expected: scanfailure.ReasonImageAuthFailed,
		},
		{
			name:     "string-based 401 Unauthorized",
			err:      fmt.Errorf("GET https://registry.io/v2/app/manifests/latest: 401 Unauthorized"),
			expected: scanfailure.ReasonImageAuthFailed,
		},
		{
			name:     "MANIFEST_UNKNOWN",
			err:      fmt.Errorf("GET https://registry.io/v2/app/manifests/latest: MANIFEST_UNKNOWN: not found"),
			expected: scanfailure.ReasonImageNotFound,
		},
		{
			name:     "generic error falls back to SBOM generation failed",
			err:      fmt.Errorf("failed to generate SBOM: some internal error"),
			expected: scanfailure.ReasonSBOMGenerationFailed,
		},
		{
			name: "transport 500 falls back to generic",
			err: &transport.Error{
				StatusCode: http.StatusInternalServerError,
			},
			expected: scanfailure.ReasonSBOMGenerationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifySBOMError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClassifySBOMStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected string
	}{
		{
			name:     "TooLarge status",
			status:   helpersv1.TooLarge,
			expected: scanfailure.ReasonSBOMTooLarge,
		},
		{
			name:     "Incomplete status",
			status:   helpersv1.Incomplete,
			expected: scanfailure.ReasonSBOMIncomplete,
		},
		{
			name:     "unknown status falls back to generic",
			status:   "SomeOtherStatus",
			expected: scanfailure.ReasonSBOMGenerationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifySBOMStatus(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}
