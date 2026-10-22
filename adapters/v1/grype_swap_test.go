package v1

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// parkingProvider parks every lookup until released and records its close.
type parkingProvider struct {
	vulnerability.Provider
	parked  chan struct{}
	release chan struct{}
	once    sync.Once
	closed  atomic.Bool
}

func newParkingProvider() *parkingProvider {
	return &parkingProvider{Provider: mock.VulnerabilityProvider(), parked: make(chan struct{}), release: make(chan struct{})}
}

func (p *parkingProvider) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	p.once.Do(func() { close(p.parked) })
	<-p.release
	return p.Provider.FindVulnerabilities(criteria...)
}

func (p *parkingProvider) Close() error {
	p.closed.Store(true)
	return nil
}

func scannableSBOM() domain.SBOM {
	const javaCPE = "cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*"
	return domain.SBOM{Name: "swap", Content: &v1beta1.SyftDocument{
		SyftSource: v1beta1.SyftSource{Type: "directory", Metadata: json.RawMessage(`{"path":"/test"}`)},
		Artifacts: []v1beta1.SyftPackage{{PackageBasicData: v1beta1.PackageBasicData{
			ID: "java", Name: "java_se", Version: "1.8.0_400", Type: "binary",
			CPEs: v1beta1.CPEs{{Value: javaCPE}},
		}}},
	}}
}

func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}

// A finished DB refresh must not wait for a running scan, nor make the readiness probe
// and the version lookup wait for it: the swap installs the new store at once, the scan
// finishes on the store it started with, and that store closes behind it.
func TestGrypeAdapter_SwapDoesNotWaitForARunningScan(t *testing.T) {
	old := newParkingProvider()
	releaseOld := sync.OnceFunc(func() { close(old.release) })
	t.Cleanup(releaseOld) // a failing run must still let the parked scan and the swap finish
	g := NewGrypeAdapter("", config.CVEMatchingOn, nil)
	g.store, g.dbStatus = old, &vulnerability.ProviderStatus{From: "db%3Aold"}

	// An update is in flight (staged before the scan starts, since on the old code the
	// scan holds the lock this needs), and its load finishes while the scan is parked.
	ch := make(chan struct{})
	g.mu.Lock()
	g.updating, g.updateChan = true, ch
	g.mu.Unlock()

	type result struct {
		report domain.CVEManifest
		err    error
	}
	scanned := make(chan result, 1)
	go func() {
		report, err := g.ScanSBOM(context.Background(), scannableSBOM())
		scanned <- result{report, err}
	}()
	<-old.parked

	replacement := &parkingProvider{Provider: mock.VulnerabilityProvider(), parked: make(chan struct{}), release: make(chan struct{})}
	close(replacement.release)
	swapped := make(chan struct{})
	go func() {
		g.finishUpdate(context.Background(), ch, true, replacement, &vulnerability.ProviderStatus{From: "db%3Anew"}, nil)
		close(swapped)
	}()

	within(t, time.Second, "Ready", func() { assert.True(t, g.Ready(context.Background())) })
	within(t, time.Second, "DBVersion", func() { assert.Equal(t, "new", g.DBVersion(context.Background())) })
	assert.False(t, old.closed.Load(), "the old store stays open while its scan runs")

	later, err := g.ScanSBOM(context.Background(), scannableSBOM())
	require.NoError(t, err)
	assert.Equal(t, "new", later.CVEDBVersion, "a scan started after the swap uses the new store")

	releaseOld()
	first := <-scanned
	require.NoError(t, first.err)
	assert.Equal(t, "old", first.report.CVEDBVersion, "the scan in flight finishes on the store it started with")
	within(t, time.Second, "the swap", func() { <-swapped })
	assert.True(t, old.closed.Load(), "the old store closes behind its last scan")
	assert.False(t, replacement.closed.Load())
}

// The scan still reports the database it matched against when none is loaded.
func TestGrypeAdapter_ScanSBOMWithoutADatabase(t *testing.T) {
	g := NewGrypeAdapter("", config.CVEMatchingOn, nil)
	_, err := g.ScanSBOM(context.Background(), scannableSBOM())
	require.ErrorIs(t, err, domain.ErrInitVulnDB)
	g.store = mock.VulnerabilityProvider(vulnerability.Vulnerability{
		PackageName: "java_se", Constraint: version.MustGetConstraint("< 1.8.0_401", version.JVMFormat),
		Reference: vulnerability.Reference{ID: "CVE-swap", Namespace: "nvd:cpe"}, CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*", "")},
	})
	g.dbStatus = &vulnerability.ProviderStatus{From: "db%3Aloaded"}
	report, err := g.ScanSBOM(context.Background(), scannableSBOM())
	require.NoError(t, err)
	assert.Equal(t, "loaded", report.CVEDBVersion)
	require.Len(t, report.Content.Matches, 1)
}
