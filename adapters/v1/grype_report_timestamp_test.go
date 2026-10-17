package v1

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reportTimeProvider struct {
	vulnerability.Provider
	searches int
	err      error
}

func (p *reportTimeProvider) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	p.searches++
	if p.err != nil {
		// Grype logs provider errors and continues matching. A provider panic is
		// recovered by its matcher boundary and returned as a fatal scan error.
		panic(p.err)
	}
	return p.Provider.FindVulnerabilities(criteria...)
}

func TestGrypeAdapter_ReportCreatedAt(t *testing.T) {
	const javaCPE = "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*"
	vuln := vulnerability.Vulnerability{
		PackageName: "java_se",
		Constraint:  version.MustGetConstraint("< 1.8.0_401", version.JVMFormat),
		Reference:   vulnerability.Reference{ID: "CVE-report-time", Namespace: "nvd:cpe"},
		CPEs:        []cpe.CPE{cpe.Must(javaCPE, "")},
	}
	t1 := time.Date(2026, 10, 17, 15, 30, 0, 123456789, time.FixedZone("test", 19800))
	t2 := t1.Add(time.Hour)
	for _, tc := range []struct {
		name        string
		withFinding bool
		matchingErr bool
		invalidSBOM bool
		missingDB   bool
	}{
		{name: "findings", withFinding: true},
		{name: "zero findings"},
		{name: "matching failure", matchingErr: true},
		{name: "conversion failure", invalidSBOM: true},
		{name: "database unavailable", missingDB: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &reportTimeProvider{Provider: mock.VulnerabilityProvider()}
			if tc.withFinding {
				provider.Provider = mock.VulnerabilityProvider(vuln)
			}
			if tc.matchingErr {
				provider.err = errors.New("test matching failure")
			}
			clockCalls := 0
			g := NewGrypeAdapter("", config.CVEMatchingOn, nil)
			g.store, g.dbStatus = provider, &vulnerability.ProviderStatus{From: "test-db"}
			if tc.missingDB {
				g.store = nil
			}
			g.now = func() time.Time {
				require.Positive(t, provider.searches, "matching must precede timestamp generation")
				clockCalls++
				return []time.Time{t1, t2}[clockCalls-1]
			}
			sbom := domain.SBOM{Name: "report-time", Content: &v1beta1.SyftDocument{
				SyftSource: v1beta1.SyftSource{Type: "directory", Metadata: json.RawMessage(`{"path":"/test"}`)},
				Artifacts: []v1beta1.SyftPackage{{PackageBasicData: v1beta1.PackageBasicData{
					ID: "java", Name: "java_se", Version: "1.8.0_400", Type: "binary",
					CPEs: v1beta1.CPEs{{Value: javaCPE}},
				}}},
			}}
			if tc.invalidSBOM {
				sbom.Content.SyftSource.Metadata = json.RawMessage(`{`)
			}
			for _, wantTime := range []time.Time{t1, t2} {
				report, err := g.ScanSBOM(context.Background(), sbom)
				if tc.matchingErr || tc.invalidSBOM || tc.missingDB {
					require.Error(t, err)
					if tc.matchingErr {
						assert.True(t, match.IsFatalError(err))
						assert.ErrorContains(t, err, "test matching failure")
					}
					assert.True(t, report.ReportCreatedAt.IsZero())
					assert.Nil(t, report.Content)
					assert.Zero(t, clockCalls, "failed evaluations must not sample successful report time")
					return
				}
				require.NoError(t, err)
				require.NotNil(t, report.Content)
				assert.Equal(t, wantTime.UTC().Truncate(time.Second), report.ReportCreatedAt)
				if tc.withFinding {
					require.Len(t, report.Content.Matches, 1)
					assert.Equal(t, vuln.ID, report.Content.Matches[0].Vulnerability.ID)
				} else {
					assert.Empty(t, report.Content.Matches)
				}
			}
			assert.Equal(t, 2, clockCalls)
		})
	}
}

func TestGrypeAdapter_ReportCreatedAtDefaultClock(t *testing.T) {
	g := NewGrypeAdapter("", config.CVEMatchingOff, nil)
	g.store = mock.VulnerabilityProvider()
	g.dbStatus = &vulnerability.ProviderStatus{}
	before := time.Now().UTC().Truncate(time.Second)
	report, err := g.ScanSBOM(context.Background(), domain.SBOM{Content: &v1beta1.SyftDocument{
		SyftSource: v1beta1.SyftSource{Type: "directory", Metadata: json.RawMessage(`{"path":"/test"}`)},
	}})
	require.NoError(t, err)
	assert.False(t, report.ReportCreatedAt.Before(before))
	assert.False(t, report.ReportCreatedAt.After(time.Now().UTC()))
	assert.Equal(t, time.UTC, report.ReportCreatedAt.Location())
}
