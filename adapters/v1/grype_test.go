package v1

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/tools"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"gotest.tools/v3/assert"
)

func Test_grypeAdapter_DBVersion(t *testing.T) {
	ctx := context.TODO()
	g := NewGrypeAdapter()
	g.Ready(ctx) // need to call ready to load the DB
	version := g.DBVersion(ctx)
	assert.Assert(t, version != "")
}

func fileToSBOM(path string) *softwarecomposition.Document {
	sbom := softwarecomposition.Document{}
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
				ImageID:            "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
				SBOMCreatorVersion: "TODO",
				Content:            fileToSBOM("testdata/alpine-sbom.json"),
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
			g := NewGrypeAdapter()
			g.Ready(ctx) // need to call ready to load the DB
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
	g := NewGrypeAdapter()
	version := g.Version(ctx)
	assert.Assert(t, version != "")
}

func fileToCVE(ctx context.Context, path string) (domain.CVEManifest, error) {
	cve := domain.CVEManifest{}
	b, err := os.ReadFile(path)
	if err != nil {
		return cve, err
	}
	var grypeDocument models.Document
	err = json.Unmarshal(b, &grypeDocument)
	if err != nil {
		return cve, err
	}
	// ugly hack to convert the source.Target to the correct type
	tb, err := json.Marshal(grypeDocument.Source.Target)
	if err != nil {
		return cve, err
	}
	var target source.ImageMetadata
	err = json.Unmarshal(tb, &target)
	if err != nil {
		return cve, err
	}
	grypeDocument.Source.Target = target
	content, err := convertToCommonContainerVulnerabilityResult(ctx, &grypeDocument, []armotypes.VulnerabilityExceptionPolicy{})
	if err != nil {
		return cve, err
	}
	cve.Content = content
	return cve, nil
}

func TestGrypeAdapter_CreateRelevantCVE(t *testing.T) {
	tests := []struct {
		name    string
		cve     string
		cvep    string
		format  string
		wantErr bool
	}{
		{
			name:   "valid CVE and CVEP produces well-formed relevant CVE",
			cve:    "testdata/alpine-cve.json",
			cvep:   "testdata/alpine-cvep.json",
			format: string(fileContent("testdata/alpine-relevant-cve.format.json")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			ctx = context.WithValue(ctx, domain.TimestampKey, time.Now().Unix())
			ctx = context.WithValue(ctx, domain.ScanIDKey, uuid.New().String())
			ctx = context.WithValue(ctx, domain.WorkloadKey, domain.ScanCommand{})
			g := NewGrypeAdapter()
			cve, err := fileToCVE(ctx, tt.cve)
			tools.EnsureSetup(t, err == nil)
			cvep, err := fileToCVE(ctx, tt.cvep)
			tools.EnsureSetup(t, err == nil)
			got, err := g.CreateRelevantCVE(ctx, cve, cvep)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateRelevantCVE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			b, err := json.Marshal(got)
			tools.EnsureSetup(t, err == nil)
			ja := jsonassert.New(t)
			ja.Assertf(string(b), tt.format)
		})
	}
}
