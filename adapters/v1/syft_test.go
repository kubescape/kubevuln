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
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/stretchr/testify/assert"
)

func fileContent(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func Test_syftAdapter_CreateSBOM(t *testing.T) {
	tests := []struct {
		name           string
		imageID        string
		format         string
		maxImageSize   int64
		options        domain.RegistryOptions
		wantErr        bool
		wantIncomplete bool
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
			name:           "big image produces incomplete SBOM",
			imageID:        "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
			format:         "null",
			maxImageSize:   1,
			wantIncomplete: true,
		},
		{
			name:    "system tests image",
			imageID: "public-registry.systest-ns-bpf7:5000/nginx:test",
			format:  "null",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxImageSize := int64(512 * 1024 * 1024)
			if tt.maxImageSize > 0 {
				maxImageSize = tt.maxImageSize
			}
			s := NewSyftAdapter(5*time.Minute, maxImageSize)
			got, err := s.CreateSBOM(context.TODO(), "name", tt.imageID, "", tt.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantIncomplete && got.Status != helpersv1.Incomplete {
				t.Errorf("CreateSBOM() want incomplete SBOM, got %v", got.Status)
				return
			}
			content, err := json.Marshal(got.Content)
			// t.Errorf(string(content))
			tools.EnsureSetup(t, err == nil)
			ja := jsonassert.New(t)
			ja.Assertf(string(content), tt.format)
		})
	}
}

func Test_syftAdapter_Version(t *testing.T) {
	s := NewSyftAdapter(5*time.Minute, 512*1024*1024)
	version := s.Version()
	assert.NotEqual(t, version, "")
}

func Test_syftAdapter_transformations(t *testing.T) {
	// Load from file
	b := fileContent("testdata/alpine-sbom.json")

	// Convert to model.Document
	var d model.Document
	if err := json.Unmarshal(b, &d); err != nil {
		tools.EnsureSetup(t, err == nil)
	}

	// Convert to syft.sbom
	sbom := toSyftModel(d)

	// Convert to domain.sbom
	s := NewSyftAdapter(5*time.Minute, 512*1024*1024)
	domainSBOM, err := s.syftToDomain(*sbom)
	tools.EnsureSetup(t, err == nil)

	// compare file with domain.sbom
	ja := jsonassert.New(t)
	b2, err := json.Marshal(domainSBOM)
	tools.EnsureSetup(t, err == nil)
	ja.Assertf(string(b2), string(b))
}
