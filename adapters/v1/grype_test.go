package v1

import (
	"context"
	"testing"

	"github.com/kinbiko/jsonassert"
	"github.com/kubescape/kubevuln/core/domain"
	"gotest.tools/v3/assert"
)

func Test_grypeAdapter_DBVersion(t *testing.T) {
	g, err := NewGrypeAdapter(context.TODO())
	assert.Assert(t, err == nil)
	version := g.DBVersion()
	assert.Assert(t, version != "")
}

func Test_grypeAdapter_ScanSBOM(t *testing.T) {
	tests := []struct {
		name    string
		sbom    domain.SBOM
		format  string
		wantErr bool
	}{
		{
			name: "hello-world",
			sbom: domain.SBOM{
				ImageID:            "library/hello-world@sha256:aa0cc8055b82dc2509bed2e19b275c8f463506616377219d9642221ab53cf9fe",
				SBOMCreatorVersion: "TODO",
				Content:            fileContent("testdata/hello-world-sbom.json"),
			},
			format: string(fileContent("testdata/hello-world-cve.format.json")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := NewGrypeAdapter(context.TODO())
			assert.Assert(t, err == nil)
			got, err := g.ScanSBOM(context.TODO(), tt.sbom)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			ja := jsonassert.New(t)
			ja.Assertf(string(got.Content), tt.format)
		})
	}
}

func Test_grypeAdapter_Version(t *testing.T) {
	g, err := NewGrypeAdapter(context.TODO())
	assert.Assert(t, err == nil)
	version := g.Version()
	assert.Assert(t, version != "")
}
