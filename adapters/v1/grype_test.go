package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"gotest.tools/v3/assert"
)

func Test_grypeAdapter_DBVersion(t *testing.T) {
	ctx := context.TODO()
	go http.ListenAndServe(":8000", http.FileServer(http.Dir("testdata")))
	g := NewGrypeAdapterFixedDB()
	g.Ready(ctx) // need to call ready to load the DB
	version := g.DBVersion(ctx)
	assert.Assert(t, version == "sha256:9be2df3d7d657bfb40ddcc68c9d00520ee7f5a34c7a26333f90cf89cefd5668a")
}

func fileToSBOM(path string) *v1beta1.Document {
	sbom := v1beta1.Document{}
	_ = json.Unmarshal(fileContent(path), &sbom)
	return &sbom
}

func Test_grypeAdapter_ScanSBOM(t *testing.T) {
	tests := []struct {
		name    string
		sbom    domain.SBOM
		format  string
		wantErr bool
	}{
		{
			name: "valid SBOM produces well-formed vulnerability list",
			sbom: domain.SBOM{
				ID:                 "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
				SBOMCreatorVersion: "TODO",
				Content:            fileToSBOM("testdata/alpine-sbom.json"),
			},
			format: string(fileContent("testdata/alpine-cve.format.json")),
		},
		{
			name: "filtered SBOM",
			sbom: domain.SBOM{
				ID:                 "927669769708707a6ec583b2f4f93eeb4d5b59e27d793a6e99134e505dac6c3c",
				SBOMCreatorVersion: "TODO",
				Content:            fileToSBOM("testdata/nginx-filtered-sbom.json"),
			},
			format: string(fileContent("testdata/nginx-filtered-cve.format.json")),
		},
	}
	go http.ListenAndServe(":8000", http.FileServer(http.Dir("testdata")))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})
			g := NewGrypeAdapterFixedDB()
			g.Ready(ctx) // need to call ready to load the DB
			got, err := g.ScanSBOM(ctx, tt.sbom)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			content, err := json.Marshal(got.Content)
			tools.EnsureSetup(t, err == nil)
			ja := jsonassert.New(t)
			ja.Assertf(string(content), tt.format)
		})
	}
}

func Test_grypeAdapter_Version(t *testing.T) {
	ctx := context.TODO()
	g := NewGrypeAdapter()
	version := g.Version(ctx)
	assert.Assert(t, version != "")
}
