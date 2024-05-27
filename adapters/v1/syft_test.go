package v1

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/kinbiko/jsonassert"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fileContent(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func Test_syftAdapter_CreateSBOM(t *testing.T) {
	tests := []struct {
		name         string
		imageID      string
		imageTag     string
		format       string
		maxImageSize int64
		maxSBOMSize  int
		options      domain.RegistryOptions
		scanTimeout  time.Duration
		wantErr      bool
		wantStatus   string
	}{
		{
			name:    "empty image produces empty SBOM",
			imageID: "library/hello-world@sha256:aa0cc8055b82dc2509bed2e19b275c8f463506616377219d9642221ab53cf9fe",
			format:  string(fileContent("testdata/hello-world-sbom.format.json")),
		},
		{
			name:    "schema v1 image produces well-formed SBOM",
			imageID: "quay.io/jitesoft/debian:stretch-slim",
			format:  string(fileContent("testdata/stretch-slim-sbom.format.json")),
		},
		{
			name:    "valid image produces well-formed SBOM",
			imageID: "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:  string(fileContent("testdata/alpine-sbom.format.json")),
		},
		{
			name:    "public image with invalid registry credentials falls back to unauthenticated and produces well-formed SBOM",
			imageID: "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:  string(fileContent("testdata/alpine-sbom.format.json")),
			options: domain.RegistryOptions{
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
			name:         "big image produces incomplete SBOM because of maxImageSize",
			imageID:      "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:       "null",
			maxImageSize: 1,
			wantStatus:   helpersv1.Incomplete,
		},
		{
			name:        "big image produces too large SBOM because of maxSBOMSize",
			imageID:     "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:      "null",
			maxSBOMSize: 1,
			wantStatus:  helpersv1.TooLarge,
		},
		{
			name:        "big image produces incomplete SBOM because of scanTimeout",
			imageID:     "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:      "null",
			scanTimeout: 1 * time.Millisecond,
			wantStatus:  helpersv1.Incomplete,
		},
		{
			name:    "system tests image",
			imageID: "public-registry.systest-ns-bpf7:5000/nginx:test",
			format:  "null",
			wantErr: true,
		},
		{
			name:     "digest as imageID",
			imageID:  "9ccc948e83b22cd3fc6919b4e3e44536530cc9426a13b8d5e07bf3b2bd1b0f22",
			imageTag: "quay.io/kubescape/kubescape:v3.0.3",
			wantErr:  false,
		},
		{
			name:     "digest as imageID 2",
			imageID:  "sha256:335bba9e861b88fa8b7bb9250bcd69b7a33f83da4fee93f9fc0eedc6f34e28ba",
			imageTag: "registry.k8s.io/kube-scheduler:v1.28.4",
			wantErr:  false,
		},
		{
			name:     "registry scan",
			imageID:  "",
			imageTag: "quay.io/matthiasb_1/kubevuln:latest",
			wantErr:  false,
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
			s := NewSyftAdapter(scanTimeout, maxImageSize, maxSBOMSize)
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
				ja := jsonassert.New(t)
				ja.Assertf(string(content), tt.format)
			}
		})
	}
}

func Test_syftAdapter_Version(t *testing.T) {
	s := NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024)
	version := s.Version()
	assert.NotEqual(t, version, "")
}

func Test_syftAdapter_transformations(t *testing.T) {
	// Load from file
	b := fileContent("testdata/alpine-sbom.json")

	// Convert to model.Document
	var d model.Document
	err := json.Unmarshal(b, &d)
	require.NoError(t, err)

	// Convert to syft.sbom
	sbom := toSyftModel(d)

	// Convert to domain.sbom
	s := NewSyftAdapter(5*time.Minute, 512*1024*1024, 20*1024*1024)
	domainSBOM, err := s.syftToDomain(*sbom)
	require.NoError(t, err)

	// compare file with domain.sbom
	ja := jsonassert.New(t)
	b2, err := json.Marshal(domainSBOM)
	require.NoError(t, err)
	ja.Assertf(string(b2), string(b))
}

func TestNormalizeImageID(t *testing.T) {
	tests := []struct {
		name     string
		imageID  string
		imageTag string
		want     string
	}{
		{
			name:     "replicaset-kubevuln-666dbffc4f-kubevuln-ca1b-6f47",
			imageID:  "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageTag: "quay.io/kubescape/kubevuln:v0.3.2",
			want:     "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:     "trap",
			imageID:  "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageTag: "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:     "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:     "trap 2",
			imageID:  "@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageTag: "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:     "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:     "trap 3",
			imageID:  "titi@toto@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			imageTag: "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
			want:     "quay.io/kubescape/kubevuln@sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a",
		},
		{
			name:     "quay.io-kubescape-kubescape-v3.0.3-88a469",
			imageID:  "86413975e2d0330176894e4f3f5987505ed27b1191f2537797fbbf345b88a469",
			imageTag: "quay.io/kubescape/kubescape:v3.0.3",
			want:     "quay.io/kubescape/kubescape@sha256:86413975e2d0330176894e4f3f5987505ed27b1191f2537797fbbf345b88a469",
		},
		{
			name:     "registry.k8s.io-kube-scheduler-v1.28.4-3d2c54",
			imageID:  "sha256:05c284c929889d88306fdb3dd14ee2d0132543740f9e247685243214fc3d2c54",
			imageTag: "registry.k8s.io/kube-scheduler:v1.28.4",
			want:     "registry.k8s.io/kube-scheduler@sha256:05c284c929889d88306fdb3dd14ee2d0132543740f9e247685243214fc3d2c54",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, normalizeImageID(tt.imageID, tt.imageTag), "normalizeImageID(%v, %v)", tt.imageID, tt.imageTag)
		})
	}
}
