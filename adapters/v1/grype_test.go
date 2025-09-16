package v1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_grypeAdapter_DBVersion(t *testing.T) {
	ctx := context.TODO()
	g, terminate, err := NewGrypeAdapterFixedDB()
	require.NoError(t, err)
	defer terminate()
	g.Ready(ctx) // need to call ready to load the DB
	version := g.DBVersion(ctx)
	assert.Equal(t, "8947f666e75c337773be86e0c6f7f4739c7549184aa994ae6236d5dbe666523b", version)
}

func fileToSBOM(path string) *v1beta1.SyftDocument {
	sbom := v1beta1.SyftDocument{}
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
				Name:               "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
				SBOMCreatorVersion: "TODO",
				Content:            fileToSBOM("testdata/alpine-sbom.json"),
			},
			format: "testdata/alpine-cve.format.json",
		},
		{
			name: "filtered SBOM",
			sbom: domain.SBOM{
				Name:               "927669769708707a6ec583b2f4f93eeb4d5b59e27d793a6e99134e505dac6c3c",
				SBOMCreatorVersion: "TODO",
				Content:            fileToSBOM("testdata/nginx-filtered-sbom.json"),
			},
			format: "testdata/nginx-filtered-cve.format.json",
		},
	}
	g, terminate, err := NewGrypeAdapterFixedDB()
	require.NoError(t, err)
	defer terminate()
	ctx := context.TODO()
	ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})
	g.Ready(ctx) // need to call ready to load the DB
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := g.ScanSBOM(ctx, tt.sbom)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScanSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			content, err := json.Marshal(got.Content)
			//os.WriteFile(tt.format, content, 0644)
			require.NoError(t, err)
			ja := jsonassert.New(t)
			ja.Assert(string(content), string(fileContent(tt.format)))
		})
	}
}

func Test_grypeAdapter_Version(t *testing.T) {
	g := NewGrypeAdapter("", false)
	version := g.Version()
	assert.NotEqual(t, version, "")
}
