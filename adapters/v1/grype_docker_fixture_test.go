//go:build dockerfixture

package v1

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/vexbatch"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_grypeAdapter_DBVersion(t *testing.T) {
	ctx := context.TODO()
	g, terminate, err := NewGrypeAdapterFixedDB()
	if errors.Is(err, ErrDockerUnavailable) {
		t.Skipf("skipping: grype offline db container unavailable (container runtime not usable): %v", err)
	}
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
	if errors.Is(err, ErrDockerUnavailable) {
		t.Skipf("skipping: grype offline db container unavailable (container runtime not usable): %v", err)
	}
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
			// observability: adapter runs in CVEMatchingOn here (non-trusted scan),
			// so the mode is annotated but the vendor-trusted flag is not.
			assert.Equal(t, string(config.CVEMatchingOn), got.Annotations[CVEMatchingModeMetadataKey])
			assert.NotContains(t, got.Annotations, VendorTrustedMatchMetadataKey)
		})
	}
}

func Test_grypeAdapter_ScanSBOMWithVEX(t *testing.T) {
	g, terminate, err := NewGrypeAdapterFixedDB()
	if errors.Is(err, ErrDockerUnavailable) {
		t.Skipf("skipping: grype offline db container unavailable (container runtime not usable): %v", err)
	}
	require.NoError(t, err)
	defer terminate()

	ctx := context.TODO()
	ctx = context.WithValue(ctx, domain.TimestampKey{}, time.Now().Unix())
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, uuid.New().String())
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})

	g.Ready(ctx)

	sbom := domain.SBOM{
		Name: "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey: "library/alpine@sha256:e2e16842c9b54d985bf1ef9242a313f36b856181f188de21313820e177002501",
		},
		SBOMCreatorVersion: "TODO",
		Content:            fileToSBOM("testdata/alpine-sbom.json"),
	}

	baseline, err := g.ScanSBOM(ctx, sbom)
	require.NoError(t, err)

	var baselineCrypto, baselineSSL bool
	for _, m := range baseline.Content.Matches {
		if m.Vulnerability.ID != "CVE-2023-1255" {
			continue
		}
		if m.Artifact.Name == "libcrypto3" {
			baselineCrypto = true
		}
		if m.Artifact.Name == "libssl3" {
			baselineSSL = true
		}
	}
	require.True(t, baselineCrypto, "baseline must contain CVE-2023-1255 for libcrypto3")
	require.True(t, baselineSSL, "baseline must contain CVE-2023-1255 for libssl3")

	documents := []vexbatch.Document{
		{
			Format: vexbatch.FormatOpenVEX,
			Path:   "testdata/external-vex-alpine.json",
		},
	}

	got, err := g.ScanSBOMWithVEX(ctx, sbom, documents)
	require.NoError(t, err)
	require.NotNil(t, got.Content)

	var cryptoIgnored, sslRemaining bool
	for _, m := range got.Content.IgnoredMatches {
		if m.Vulnerability.ID == "CVE-2023-1255" && m.Artifact.Name == "libcrypto3" {
			cryptoIgnored = true
		}
	}

	for _, m := range got.Content.Matches {
		if m.Vulnerability.ID == "CVE-2023-1255" && m.Artifact.Name == "libssl3" {
			sslRemaining = true
		}
	}

	assert.True(t, cryptoIgnored, "VEX-suppressed libcrypto3 finding must move to IgnoredMatches")
	assert.True(t, sslRemaining, "unrelated libssl3 finding must remain in Matches")

	missingIdentitySBOM := sbom
	missingIdentitySBOM.Annotations = nil

	missingIdentity, err := g.ScanSBOMWithVEX(ctx, missingIdentitySBOM, documents)
	require.NoError(t, err)

	var missingIdentityCrypto bool
	for _, m := range missingIdentity.Content.Matches {
		if m.Vulnerability.ID == "CVE-2023-1255" && m.Artifact.Name == "libcrypto3" {
			missingIdentityCrypto = true
		}
	}
	assert.True(t, missingIdentityCrypto, "VEX must not suppress findings when scan identity is missing")

	mismatchedIdentitySBOM := sbom
	mismatchedIdentitySBOM.Annotations = map[string]string{
		helpersv1.ImageIDMetadataKey: "library/alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}

	mismatchedIdentity, err := g.ScanSBOMWithVEX(ctx, mismatchedIdentitySBOM, documents)
	require.NoError(t, err)

	var mismatchedIdentityCrypto bool
	for _, m := range mismatchedIdentity.Content.Matches {
		if m.Vulnerability.ID == "CVE-2023-1255" && m.Artifact.Name == "libcrypto3" {
			mismatchedIdentityCrypto = true
		}
	}
	assert.True(t, mismatchedIdentityCrypto, "VEX must not suppress findings for a mismatched scan identity")
}
