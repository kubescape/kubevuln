package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/safefetch"
	"github.com/kubescape/kubevuln/internal/vexbatch"
	"github.com/kubescape/kubevuln/internal/vexsource"
	"github.com/stretchr/testify/require"
)

const validExternalOpenVEX = `{
	"@context": "https://openvex.dev/ns/v0.2.0",
	"@id": "https://example.com/vex-1",
	"author": "test",
	"timestamp": "2026-01-01T00:00:00Z",
	"version": 1,
	"statements": [
		{
			"vulnerability": {"name": "CVE-2021-44228"},
			"products": [{"@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0"}],
			"status": "not_affected",
			"justification": "vulnerable_code_not_present"
		}
	]
}`

type vexAwareTestScanner struct {
	ports.CVEScanner
	vexCalls   int
	plainCalls int
	documents  []vexbatch.Document
	paths      []string
	vexErr     error
}

func (s *vexAwareTestScanner) ScanSBOM(ctx context.Context, sbom domain.SBOM) (domain.CVEManifest, error) {
	s.plainCalls++
	return s.CVEScanner.ScanSBOM(ctx, sbom)
}

func (s *vexAwareTestScanner) ScanSBOMWithVEX(ctx context.Context, sbom domain.SBOM, documents []vexbatch.Document) (domain.CVEManifest, error) {
	s.vexCalls++
	s.documents = append(s.documents, documents...)
	for _, document := range documents {
		s.paths = append(s.paths, document.Path)
		if _, err := os.Stat(document.Path); err != nil {
			return domain.CVEManifest{}, err
		}
	}
	if s.vexErr != nil {
		return domain.CVEManifest{}, s.vexErr
	}
	return s.CVEScanner.ScanSBOM(ctx, sbom)
}

type vexRecordingPlatform struct {
	ports.Platform
	reported []error
}

func (p *vexRecordingPlatform) ReportError(ctx context.Context, err error) error {
	p.reported = append(p.reported, err)
	return nil
}

func newVEXTestService(scanner ports.CVEScanner, server *httptest.Server, sources []vexsource.Source) *ScanService {
	platform := &vexRecordingPlatform{Platform: adapters.NewMockPlatform(true, nil)}
	service := NewScanService(nil, nil, scanner, nil, platform, nil, false, false, true, false, false)
	service.SetVEXSources(sources)
	service.vexIngestor = vexsource.Ingestor{
		Fetcher: &safefetch.Fetcher{
			Client:   server.Client(),
			MaxBytes: 1 << 20,
		},
	}
	return service
}

func TestScanSBOMWithExternalVEXKeepsPartialSuccessAndCleansStagedFiles(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/valid", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validExternalOpenVEX))
	})
	mux.HandleFunc("/unavailable", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	scanner := &vexAwareTestScanner{CVEScanner: adapters.NewMockCVEAdapter()}
	service := newVEXTestService(scanner, server, []vexsource.Source{
		{URL: server.URL + "/valid"},
		{URL: server.URL + "/unavailable"},
	})

	manifest, err := service.scanSBOM(context.Background(), domain.SBOM{Name: "image"})
	require.NoError(t, err)
	require.NotNil(t, manifest.Content)
	require.Equal(t, 1, scanner.vexCalls)
	require.Zero(t, scanner.plainCalls)
	require.Len(t, scanner.documents, 1)
	require.Len(t, scanner.paths, 1)
	_, err = os.Stat(scanner.paths[0])
	require.ErrorIs(t, err, os.ErrNotExist)

	platform := service.platform.(*vexRecordingPlatform)
	require.Empty(t, platform.reported, "optional VEX errors must not mark the backend job failed")
}

func TestScanSBOMFallsBackWhenGrypeCannotApplyExternalVEX(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validExternalOpenVEX))
	}))
	defer server.Close()

	scanner := &vexAwareTestScanner{
		CVEScanner: adapters.NewMockCVEAdapter(),
		vexErr:     errors.New("VEX processor failed"),
	}
	service := newVEXTestService(scanner, server, []vexsource.Source{{URL: server.URL}})

	manifest, err := service.scanSBOM(context.Background(), domain.SBOM{Name: "image"})
	require.NoError(t, err)
	require.NotNil(t, manifest.Content)
	require.Equal(t, 1, scanner.vexCalls)
	require.Equal(t, 1, scanner.plainCalls)
	_, err = os.Stat(scanner.paths[0])
	require.ErrorIs(t, err, os.ErrNotExist)

	platform := service.platform.(*vexRecordingPlatform)
	require.Empty(t, platform.reported, "optional VEX errors must not mark the backend job failed")
}

func TestCVECachingVersionIsScopedToExternalVEXSources(t *testing.T) {
	scanner := adapters.NewMockCVEAdapter()
	service := NewScanService(nil, nil, scanner, nil, adapters.NewMockPlatform(true, nil), nil, false, false, true, false, false)
	require.Equal(t, scanner.Version(), service.cveCacheVersion())

	service.SetVEXSources([]vexsource.Source{{URL: "https://vex.example.com/feed.json"}})
	withOpenVEX := service.cveCacheVersion()
	require.NotEqual(t, scanner.Version(), withOpenVEX)

	service.SetVEXSources([]vexsource.Source{{URL: "https://vex.example.com/other.json"}})
	require.NotEqual(t, withOpenVEX, service.cveCacheVersion())
}

func TestScanSBOMFallsBackWhenAllExternalSourcesFail(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	scanner := &vexAwareTestScanner{CVEScanner: adapters.NewMockCVEAdapter()}
	service := newVEXTestService(scanner, server, []vexsource.Source{{URL: server.URL}})

	manifest, err := service.scanSBOM(context.Background(), domain.SBOM{Name: "image"})
	require.NoError(t, err)
	require.NotNil(t, manifest.Content)
	require.Zero(t, scanner.vexCalls)
	require.Equal(t, 1, scanner.plainCalls)

	platform := service.platform.(*vexRecordingPlatform)
	require.Empty(t, platform.reported, "optional VEX errors must not mark the backend job failed")
}

// TestScanSBOMRecordsExternalVEXOutcome checks each way an evaluation with configured
// sources can end is counted under its own outcome, so an operator can tell from
// /metrics alone whether findings were produced with the configured feeds or without.
func TestScanSBOMRecordsExternalVEXOutcome(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unavailable" {
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validExternalOpenVEX))
	}))
	defer server.Close()

	tests := []struct {
		name    string
		scanner ports.CVEScanner
		sources []vexsource.Source
		want    string
	}{
		{
			name:    "documents applied",
			scanner: &vexAwareTestScanner{CVEScanner: adapters.NewMockCVEAdapter()},
			sources: []vexsource.Source{{URL: server.URL + "/feed"}},
			want:    metrics.ExternalVEXScanApplied,
		},
		{
			name:    "every source failed",
			scanner: &vexAwareTestScanner{CVEScanner: adapters.NewMockCVEAdapter()},
			sources: []vexsource.Source{{URL: server.URL + "/unavailable"}},
			want:    metrics.ExternalVEXScanNoDocuments,
		},
		{
			name: "grype could not apply the documents",
			scanner: &vexAwareTestScanner{
				CVEScanner: adapters.NewMockCVEAdapter(),
				vexErr:     errors.New("VEX processor failed"),
			},
			sources: []vexsource.Source{{URL: server.URL + "/feed"}},
			want:    metrics.ExternalVEXScanApplyFailed,
		},
		{
			name:    "scanner cannot apply VEX",
			scanner: adapters.NewMockCVEAdapter(),
			sources: []vexsource.Source{{URL: server.URL + "/feed"}},
			want:    metrics.ExternalVEXScanUnsupported,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := metrics.New()
			require.NoError(t, err)
			t.Cleanup(func() { _ = m.Shutdown(context.Background()) })

			service := newVEXTestService(tt.scanner, server, tt.sources)
			_, err = service.scanSBOM(context.Background(), domain.SBOM{Name: "image"})
			require.NoError(t, err)

			body := scrapeMetrics(t, m)
			require.Contains(t, body, `kubevuln_external_vex_scans_total{outcome="`+tt.want+`"} 1`)
			require.Equal(t, 1, strings.Count(body, "kubevuln_external_vex_scans_total{"),
				"one evaluation must record exactly one outcome")
		})
	}
}

// Without configured sources there is no external VEX outcome to report, so a deployment
// that never configured feeds must not grow kubevuln_external_vex_scans_total series.
func TestScanSBOMWithoutExternalVEXSourcesRecordsNoOutcome(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })

	service := NewScanService(nil, nil, adapters.NewMockCVEAdapter(), nil, adapters.NewMockPlatform(true, nil), nil, false, false, true, false, false)
	_, err = service.scanSBOM(context.Background(), domain.SBOM{Name: "image"})
	require.NoError(t, err)
	_, err = service.scanSBOMWithVEX(context.Background(), domain.SBOM{Name: "image"}, nil)
	require.NoError(t, err)

	require.NotContains(t, scrapeMetrics(t, m), "kubevuln_external_vex_")
}

func scrapeMetrics(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, w.Code)
	return w.Body.String()
}
