//go:build integration

package v1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kinbiko/jsonassert"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/require"
)

// Test_syftAdapter_CreateSBOM pulls real images from public registries (Docker Hub, quay.io,
// gcr.io, registry.k8s.io). It is gated behind the "integration" build tag so `go test ./adapters/v1`
// stays fast and hermetic by default; run it explicitly with `go test -tags=integration ./adapters/v1`.
func Test_syftAdapter_CreateSBOM(t *testing.T) {
	tests := []struct {
		name              string
		imageID           string
		imageTag          string
		format            string
		maxImageSize      int64
		maxSBOMSize       int
		options           domain.RegistryOptions
		scanTimeout       time.Duration
		scanEmbeddedSBOMs bool
		wantErr           bool
		wantStatus        string
	}{
		{
			// Platform is pinned explicitly so this assertion is stable across host
			// architectures: with no platform requested, stereoscope's registry provider
			// defaults to runtime.GOARCH (see defaultPlatformIfNil in
			// github.com/anchore/stereoscope/pkg/image/oci), which would otherwise resolve
			// a different manifest - and produce a different SBOM than this fixture - on
			// an arm64 runner than on the amd64 runner the fixture was captured on.
			name:    "empty image produces empty SBOM",
			imageID: "library/hello-world@sha256:aa0cc8055b82dc2509bed2e19b275c8f463506616377219d9642221ab53cf9fe",
			format:  "testdata/hello-world-sbom.format.json",
			options: domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:    "schema v1 image produces well-formed SBOM",
			imageID: "quay.io/jitesoft/debian:stretch-slim",
			format:  "testdata/stretch-slim-sbom.format.json",
			options: domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:    "valid image produces well-formed SBOM",
			imageID: "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:  "testdata/alpine-sbom.format.json",
			options: domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:    "public image with invalid registry credentials falls back to unauthenticated and produces well-formed SBOM",
			imageID: "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:  "testdata/alpine-sbom.format.json",
			options: domain.RegistryOptions{
				Platform: "linux/amd64",
				Credentials: []domain.RegistryCredentials{
					{
						Authority: "index.docker.io",
						Username:  "username",
						Password:  "password",
						Token:     "token",
					},
				},
			},
		},
		{
			name:         "big image produces too large SBOM because of maxImageSize",
			imageID:      "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:       "",
			maxImageSize: 1,
			wantStatus:   helpersv1.TooLarge,
			options:      domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:        "big image produces too large SBOM because of maxSBOMSize",
			imageID:     "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:      "",
			maxSBOMSize: 1,
			wantStatus:  helpersv1.TooLarge,
			options:     domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:        "big image produces incomplete SBOM because of scanTimeout",
			imageID:     "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:      "",
			scanTimeout: 1 * time.Millisecond,
			wantStatus:  helpersv1.Incomplete,
			options:     domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:    "system tests image",
			imageID: "public-registry.systest-ns-bpf7:5000/nginx:test",
			format:  "",
			wantErr: true,
		},
		{
			name:     "digest as imageID",
			imageID:  "9ccc948e83b22cd3fc6919b4e3e44536530cc9426a13b8d5e07bf3b2bd1b0f22",
			imageTag: "quay.io/kubescape/kubescape:v3.0.3",
			wantErr:  false,
			options:  domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:     "digest as imageID 2",
			imageID:  "sha256:335bba9e861b88fa8b7bb9250bcd69b7a33f83da4fee93f9fc0eedc6f34e28ba",
			imageTag: "registry.k8s.io/kube-scheduler:v1.28.4",
			wantErr:  false,
			options:  domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:     "registry scan",
			imageID:  "",
			imageTag: "quay.io/matthiasb_1/kubevuln:latest",
			wantErr:  false,
			options:  domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:              "embedded sbom scan",
			imageTag:          "docker.io/janeisklar/alpine:3.15-sbom",
			scanEmbeddedSBOMs: true,
			wantErr:           false,
			format:            "testdata/alpine-embedded-sbom.json",
			options:           domain.RegistryOptions{Platform: "linux/amd64"},
		},
		{
			name:    "public image with invalid credentials falls back to unauthenticated",
			imageID: "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:  "testdata/alpine-sbom.format.json",
			options: domain.RegistryOptions{
				Platform: "linux/amd64",
				Credentials: []domain.RegistryCredentials{
					{
						Authority: "index.docker.io",
						Username:  "username",
						Password:  "badpassword",
					},
				},
			},
		},
		{
			name:    "public GCR image with invalid credentials attempts ADC then falls back to unauthenticated",
			imageID: "gcr.io/google-containers/pause:3.1",
			options: domain.RegistryOptions{
				Credentials: []domain.RegistryCredentials{
					{
						Authority: "gcr.io",
						Username:  "username",
						Password:  "badpassword",
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "GCP registry with no ADC falls back to anonymous and fails gracefully",
			imageID: "gcr.io/nonexistent-project/nonexistent-image:latest",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxImageSize := int64(512 * 1024 * 1024)
			if tt.maxImageSize > 0 {
				maxImageSize = tt.maxImageSize
			}
			maxSBOMSize := 20 * 1024 * 1024
			if tt.maxSBOMSize > 0 {
				maxSBOMSize = tt.maxSBOMSize
			}
			scanTimeout := 5 * time.Minute
			if tt.scanTimeout > 0 {
				scanTimeout = tt.scanTimeout
			}
			s := NewSyftAdapter(scanTimeout, maxImageSize, maxSBOMSize, tt.scanEmbeddedSBOMs, nil)
			got, err := s.CreateSBOM(context.TODO(), "name", tt.imageID, tt.imageTag, tt.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantStatus != "" && got.Status != tt.wantStatus {
				t.Errorf("CreateSBOM() want %v SBOM, got %v", tt.wantStatus, got.Status)
				return
			}
			content, err := json.Marshal(got.Content)
			require.NoError(t, err)
			if tt.format != "" {
				//os.WriteFile(tt.format, content, 0644)
				ja := jsonassert.New(t)
				ja.Assert(string(content), string(fileContent(tt.format)))
			}
		})
	}
}
