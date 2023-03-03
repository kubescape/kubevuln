package v1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"gotest.tools/v3/assert"
)

func Test_grypeAdapter_DBVersion(t *testing.T) {
	ctx := context.TODO()
	g, err := NewGrypeAdapter(ctx)
	tools.EnsureSetup(t, err == nil)
	version := g.DBVersion(ctx)
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
			name: "valid SBOM produces well-formed vulnerability list",
			sbom: domain.SBOM{
				ImageID:            "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
				SBOMCreatorVersion: "TODO",
				Content:            fileContent("testdata/alpine-sbom.json"),
			},
			format: string(fileContent("testdata/alpine-cve.format.json")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey, domain.ScanCommand{})
			g, err := NewGrypeAdapter(ctx)
			tools.EnsureSetup(t, err == nil)
			got, err := g.ScanSBOM(ctx, tt.sbom, nil)
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
	g, err := NewGrypeAdapter(ctx)
	tools.EnsureSetup(t, err == nil)
	version := g.Version(ctx)
	assert.Assert(t, version != "")
}
