package services

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/pkg/vex/join"
	"github.com/kubescape/kubevuln/pkg/vex/parser"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanService_SetVEXJoinEngine_SuppressesFindings(t *testing.T) {
	ctx := context.Background()

	// Initialize mock dependencies
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	cveAdapter := adapters.NewMockCVEAdapter()
	seRepo := &repositories.NoOpSecurityExceptionRepository{}
	platform := adapters.NewMockPlatform(true, seRepo)
	relevancy := adapters.NewMockRelevancyAdapter()

	service := NewScanService(sbomAdapter, nil, cveAdapter, nil, platform, relevancy, false, false, false, false, false)

	// Create VEX statements
	statements := []parser.VEXStatement{
		{
			CVE:           "CVE-2026-9999",
			Status:        "not_affected",
			Justification: "vulnerable_code_not_present",
			SourceURL:     "http://vendor.example.com/vex",
			StatementRef:  "http://vendor.example.com/vex/statement/1",
			ProductPURL:   "pkg:alpine/openssl@3.0.2",
			Timestamp:     time.Now(),
		},
	}

	joinEngine := join.NewJoinEngine(statements)
	service.SetVEXJoinEngine(joinEngine)

	// Construct input manifest with raw CVE
	manifest := domain.CVEManifest{
		Content: &v1beta1.GrypeDocument{
			Matches: []v1beta1.Match{
				{
					Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2026-9999"}},
					Artifact:      v1beta1.GrypePackage{PURL: "pkg:alpine/openssl@3.0.2"},
				},
				{
					Vulnerability: v1beta1.Vulnerability{VulnerabilityMetadata: v1beta1.VulnerabilityMetadata{ID: "CVE-2026-1111"}},
					Artifact:      v1beta1.GrypePackage{PURL: "pkg:alpine/curl@7.88.0"},
				},
			},
		},
	}

	filtered, complete := service.applyExceptionsToManifest(ctx, manifest)

	require.True(t, complete)
	require.NotNil(t, filtered.Content)

	// Verify CVE-2026-9999 was suppressed and CVE-2026-1111 remains
	require.Len(t, filtered.Content.Matches, 1)
	assert.Equal(t, "CVE-2026-1111", filtered.Content.Matches[0].Vulnerability.ID)

	// Verify provenance details on IgnoredMatches
	require.Len(t, filtered.Content.IgnoredMatches, 1)
	assert.Equal(t, "CVE-2026-9999", filtered.Content.IgnoredMatches[0].Match.Vulnerability.ID)
	require.Len(t, filtered.Content.IgnoredMatches[0].AppliedIgnoreRules, 1)
	assert.Equal(t, "VEXSource", filtered.Content.IgnoredMatches[0].AppliedIgnoreRules[0].SourceKind)
	assert.Equal(t, "http://vendor.example.com/vex", filtered.Content.IgnoredMatches[0].AppliedIgnoreRules[0].SourceName)
	assert.Equal(t, "http://vendor.example.com/vex/statement/1", filtered.Content.IgnoredMatches[0].AppliedIgnoreRules[0].SourceNamespace)
	assert.Equal(t, "vulnerable_code_not_present", filtered.Content.IgnoredMatches[0].AppliedIgnoreRules[0].Justification)
}
