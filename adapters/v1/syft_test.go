package v1

import (
	"context"
	"os"
	"testing"

	"github.com/kinbiko/jsonassert"
	"github.com/kubescape/kubevuln/core/domain"
	"gotest.tools/v3/assert"
)

func fileContent(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func Test_syftAdapter_CreateSBOM(t *testing.T) {
	tests := []struct {
		name    string
		imageID string
		format  string
		options domain.RegistryOptions
		wantErr bool
	}{
		{
			name:    "hello-world",
			imageID: "library/hello-world@sha256:aa0cc8055b82dc2509bed2e19b275c8f463506616377219d9642221ab53cf9fe",
			format:  string(fileContent("testdata/hello-world-sbom.format.json")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSyftAdapter()
			got, err := s.CreateSBOM(context.TODO(), tt.imageID, tt.options)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			ja := jsonassert.New(t)
			ja.Assertf(string(got.Content), tt.format)
		})
	}
}

func Test_syftAdapter_Version(t *testing.T) {
	s := NewSyftAdapter()
	version := s.Version()
	assert.Assert(t, version != "")
}
