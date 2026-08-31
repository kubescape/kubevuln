package v1

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/google/uuid"
	"github.com/kinbiko/jsonassert"
	"github.com/kubescape/kubevuln/config"
	"github.com/kubescape/kubevuln/core/domain"
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

func Test_grypeAdapter_Version(t *testing.T) {
	g := NewGrypeAdapter("", config.CVEMatchingOn, nil)
	version := g.Version()
	assert.NotEqual(t, version, "")
}

func Test_grypeAdapter_resolveUseDefaultMatchers(t *testing.T) {
	trusted := []string{"echo", "chainguard", "wolfi", "minimos"}
	echoDistro := &distro.Distro{Type: distro.Echo}
	ubuntuDistro := &distro.Distro{Type: distro.Ubuntu}

	tests := []struct {
		name string
		mode config.CVEMatchingMode
		dist *distro.Distro
		want bool
	}{
		{name: "off + trusted distro -> default matchers", mode: config.CVEMatchingOff, dist: echoDistro, want: true},
		{name: "off + untrusted distro -> default matchers", mode: config.CVEMatchingOff, dist: ubuntuDistro, want: true},
		{name: "off + nil distro -> default matchers", mode: config.CVEMatchingOff, dist: nil, want: true},
		{name: "on + trusted distro -> CPE matchers", mode: config.CVEMatchingOn, dist: echoDistro, want: false},
		{name: "on + untrusted distro -> CPE matchers", mode: config.CVEMatchingOn, dist: ubuntuDistro, want: false},
		{name: "on + nil distro -> CPE matchers", mode: config.CVEMatchingOn, dist: nil, want: false},
		{name: "adaptive + trusted distro -> default matchers", mode: config.CVEMatchingAdaptive, dist: echoDistro, want: true},
		{name: "adaptive + untrusted distro -> CPE matchers", mode: config.CVEMatchingAdaptive, dist: ubuntuDistro, want: false},
		{name: "adaptive + nil distro -> CPE matchers", mode: config.CVEMatchingAdaptive, dist: nil, want: false},
		{name: "unknown mode falls back to CPE matchers", mode: config.CVEMatchingMode("bogus"), dist: echoDistro, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &GrypeAdapter{matchingMode: tt.mode, trustedVendors: buildTrustedVendorSet(trusted)}
			assert.Equal(t, tt.want, g.resolveUseDefaultMatchers(tt.dist))
		})
	}
}

type mockProvider struct {
	vulnerability.Provider
}

func (m *mockProvider) Close() error { return nil }

// closeTrackingProvider records whether/how-many-times Close was called, so tests can
// prove the double-buffer swap in finishUpdate closes the *old* store and installs the
// *new* one, rather than the two being indistinguishable (as they were when both the old
// and new store in a test were the same *mockProvider instance).
type closeTrackingProvider struct {
	vulnerability.Provider
	closed int32
}

func (p *closeTrackingProvider) Close() error {
	atomic.AddInt32(&p.closed, 1)
	return nil
}

// waitForNotUpdating polls until a background update finishes (g.updating flips back to
// false) or fails the test after a short deadline. Background goroutines spawned by
// updateDBBackground/finishUpdate are not otherwise observable from the outside, and
// letting them outlive the test is a source of -race flakiness in later tests.
func waitForNotUpdating(t *testing.T, g *GrypeAdapter) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.RLock()
		updating := g.updating
		g.mu.RUnlock()
		if !updating {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background update did not finish in time")
}

func Test_grypeAdapter_NonBlockingReady(t *testing.T) {
	ctx := context.Background()
	oldStore := &closeTrackingProvider{}
	newStore := &closeTrackingProvider{}
	blockLoad := make(chan struct{})

	g := &GrypeAdapter{
		store:             oldStore,
		dbStatus:          &vulnerability.ProviderStatus{From: "schema:v6%3Atest-checksum"},
		nextUpdateAttempt: time.Now().Add(24 * time.Hour),
		loadDB: func(distCfg distribution.Config, installCfg installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			<-blockLoad
			return newStore, &vulnerability.ProviderStatus{From: "schema:v6%3Anew-checksum"}, nil
		},
	}

	// Initial check with valid DB returns ready immediately
	require.True(t, g.Ready(ctx))
	assert.Equal(t, "test-checksum", g.DBVersion(ctx))

	// Force the next update to be due, to trigger the background update check
	g.mu.Lock()
	g.nextUpdateAttempt = time.Now().Add(-time.Minute)
	g.mu.Unlock()

	// Trigger Ready - should launch background update without blocking
	readyCh := make(chan bool, 1)
	go func() {
		readyCh <- g.Ready(ctx)
	}()

	select {
	case isReady := <-readyCh:
		// With an existing DB, Ready returns immediately true while update runs in background
		assert.True(t, isReady)
	case <-time.After(1 * time.Second):
		t.Fatal("Ready() blocked waiting for DB update, causing lock contention")
	}

	// Verify DBVersion can acquire read locks concurrently while background update is active
	version := g.DBVersion(ctx)
	assert.Equal(t, "test-checksum", version)

	// Verify background update is active under RLock
	g.mu.RLock()
	isUpdating := g.updating
	g.mu.RUnlock()
	assert.True(t, isUpdating, "background update should be active")

	// Unblock background loadDB and wait for the swap to actually land before asserting on it
	close(blockLoad)
	waitForNotUpdating(t, g)

	g.mu.RLock()
	defer g.mu.RUnlock()
	assert.Same(t, newStore, g.store, "the new provider from loadDB must be installed as the active store")
	assert.Equal(t, int32(1), atomic.LoadInt32(&oldStore.closed), "the previous store must be closed exactly once after the swap")
	assert.Equal(t, int32(0), atomic.LoadInt32(&newStore.closed), "the newly installed store must not be closed")
}

// Reproduces the exact scenario from the mentor review: a cold start (no DB ever loaded)
// where loadDB keeps failing. Before nextUpdateAttempt existed, needsUpdate short-circuited
// on dbStatus == nil, so every readiness probe re-launched a full download attempt with no
// back-off. Ready() blocks synchronously on cold start until the background attempt
// finishes, so looping it here deterministically exercises that path without a timing race.
func Test_grypeAdapter_Ready_backsOffAfterFailedColdStart(t *testing.T) {
	ctx := context.Background()
	var calls int32
	g := &GrypeAdapter{
		loadDB: func(distribution.Config, installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			atomic.AddInt32(&calls, 1)
			return nil, nil, errors.New("network down")
		},
	}

	for i := 0; i < 5; i++ {
		require.False(t, g.Ready(ctx))
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "cold-start failures must back off, not fire once per probe")

	g.mu.RLock()
	defer g.mu.RUnlock()
	assert.True(t, g.nextUpdateAttempt.After(time.Now()), "a failed cold start must schedule a future retry instead of leaving Ready always due")
}

// A load that returns no Go error but a ProviderStatus.Error is not a usable DB. Before this
// was treated as a failure, it was installed as g.store/g.dbStatus and lastDbUpdate was set
// to now, wedging the pod NotReady for 24h with nothing to trigger a retry or a restart.
func Test_grypeAdapter_Ready_treatsStatusErrorAsFailure(t *testing.T) {
	ctx := context.Background()
	statusErr := errors.New("corrupt db")
	badStore := &closeTrackingProvider{}
	g := &GrypeAdapter{
		loadDB: func(distribution.Config, installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			return badStore, &vulnerability.ProviderStatus{Error: statusErr}, nil
		},
	}

	require.False(t, g.Ready(ctx))

	g.mu.RLock()
	defer g.mu.RUnlock()
	assert.Nil(t, g.store, "a load whose status carries an error must not be installed as the active store")
	assert.Equal(t, int32(1), atomic.LoadInt32(&badStore.closed), "the unusable store must be closed rather than leaked")
	assert.True(t, g.nextUpdateAttempt.Before(time.Now().Add(6*time.Minute)), "must schedule a short retry, not the 24h success interval")
}

// Concurrent readiness probes racing Ready() while an update is in flight must not launch a
// second background load - the single-flight guard (g.updating) is only meant to be released
// once the actual load returns, not merely once updateDBBackground's own wait gives up.
func Test_grypeAdapter_Ready_singleFlightUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	var calls int32
	blockLoad := make(chan struct{})
	g := &GrypeAdapter{
		store:             &mockProvider{},
		dbStatus:          &vulnerability.ProviderStatus{From: "schema:v6%3Atest-checksum"},
		nextUpdateAttempt: time.Now().Add(-time.Minute),
		loadDB: func(distribution.Config, installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			atomic.AddInt32(&calls, 1)
			<-blockLoad
			return &mockProvider{}, &vulnerability.ProviderStatus{From: "schema:v6%3Anew"}, nil
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Ready(ctx)
		}()
	}
	wg.Wait()

	close(blockLoad)
	waitForNotUpdating(t, g)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "concurrent Ready() calls must not launch more than one background load")
}

func forceUpdateDue(g *GrypeAdapter) {
	g.mu.Lock()
	g.nextUpdateAttempt = time.Now().Add(-time.Minute)
	g.mu.Unlock()
}

// A warm-path DB update whose load never returns (an uncancellable download hung on a
// stalled connection) must not latch g.updating true forever: updateDBBackground abandons it
// after stuckUpdateTimeout, releases the guard, and schedules a retry. A retry launched while
// the stuck load is still running must NOT start a second concurrent load against the same DB
// cache dir; once the stuck load's goroutine finally exits, the next retry loads and installs
// a fresh DB. Before #900 the guard stayed set for the pod's lifetime and no further update
// was ever attempted.
func Test_grypeAdapter_Ready_recoversFromStuckWarmUpdate(t *testing.T) {
	ctx := context.Background()
	oldStore := &closeTrackingProvider{}
	newStore := &closeTrackingProvider{}
	stuck := make(chan struct{})
	var loadCalls int32

	g := &GrypeAdapter{
		store:              oldStore,
		dbStatus:           &vulnerability.ProviderStatus{From: "schema:v6%3Aold"},
		nextUpdateAttempt:  time.Now().Add(-time.Minute),
		stuckUpdateTimeout: 20 * time.Millisecond,
		loadDB: func(distribution.Config, installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			if atomic.AddInt32(&loadCalls, 1) == 1 {
				<-stuck // first load models an uncancellable download that never returns
				return nil, nil, errors.New("unblocked later")
			}
			return newStore, &vulnerability.ProviderStatus{From: "schema:v6%3Anew"}, nil
		},
	}

	// 1. First probe launches the update; the load hangs; updateDBBackground abandons it.
	require.True(t, g.Ready(ctx), "pod stays Ready while the stuck update is abandoned")
	require.Eventually(t, func() bool {
		g.mu.RLock()
		defer g.mu.RUnlock()
		return !g.updating && g.updateChan == nil
	}, 2*time.Second, 5*time.Millisecond, "a stuck warm update must be abandoned, not left latched")

	g.mu.RLock()
	assert.True(t, g.nextUpdateAttempt.After(time.Now()), "an abandoned update must schedule a bounded retry")
	assert.Same(t, oldStore, g.store, "the existing DB keeps serving while the stuck load is abandoned")
	g.mu.RUnlock()

	// 2. A retry while the stuck load still holds loadMu must skip rather than start a second
	//    concurrent load against the same DB cache dir, and must reschedule.
	forceUpdateDue(g)
	require.True(t, g.Ready(ctx))
	require.Eventually(t, func() bool {
		g.mu.RLock()
		defer g.mu.RUnlock()
		return !g.updating
	}, 2*time.Second, 5*time.Millisecond, "the bounced retry must reschedule")
	assert.Equal(t, int32(1), atomic.LoadInt32(&loadCalls), "no second load runs while the stuck one holds the DB cache dir")
	g.mu.RLock()
	assert.Same(t, oldStore, g.store)
	g.mu.RUnlock()

	// 3. The stuck load finally exits, releasing loadMu; a retry now loads and installs.
	close(stuck)
	require.Eventually(t, func() bool {
		g.mu.Lock()
		g.nextUpdateAttempt = time.Now().Add(-time.Minute)
		updating := g.updating
		g.mu.Unlock()
		if !updating {
			g.Ready(ctx)
		}
		g.mu.RLock()
		defer g.mu.RUnlock()
		return g.store == newStore
	}, 3*time.Second, 15*time.Millisecond, "once the stuck load releases loadMu, a retry installs a fresh DB")

	g.mu.RLock()
	defer g.mu.RUnlock()
	assert.Equal(t, int32(2), atomic.LoadInt32(&loadCalls), "exactly one load ran after the stuck one was released")
	assert.Equal(t, int32(1), atomic.LoadInt32(&oldStore.closed), "the superseded store is closed once the new one is installed")
}

// A load that is slow but returns within stuckUpdateTimeout is installed normally: the
// stuck-load handling and loadMu serialization must not interfere with an ordinary refresh.
func Test_grypeAdapter_Ready_slowLoadWithinTimeoutStillInstalls(t *testing.T) {
	ctx := context.Background()
	oldStore := &closeTrackingProvider{}
	newStore := &closeTrackingProvider{}
	g := &GrypeAdapter{
		store:              oldStore,
		dbStatus:           &vulnerability.ProviderStatus{From: "schema:v6%3Aold"},
		nextUpdateAttempt:  time.Now().Add(-time.Minute),
		stuckUpdateTimeout: 500 * time.Millisecond,
		loadDB: func(distribution.Config, installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			time.Sleep(40 * time.Millisecond)
			return newStore, &vulnerability.ProviderStatus{From: "schema:v6%3Anew"}, nil
		},
	}

	require.True(t, g.Ready(ctx))
	waitForNotUpdating(t, g)

	g.mu.RLock()
	defer g.mu.RUnlock()
	assert.Same(t, newStore, g.store, "a slow-but-returning load must still be installed")
	assert.Equal(t, int32(1), atomic.LoadInt32(&oldStore.closed), "the previous store is closed after the swap")
}

// A load that finally returns after updateDBBackground abandoned it as stuck must be
// discarded, not installed: its provider is closed and g.store / g.nextUpdateAttempt are left
// as abandonStuckUpdate set them, so a slow load cannot silently overwrite a newer one or
// undo the retry schedule (see #900, acceptance criterion 2).
func Test_grypeAdapter_finishUpdate_discardsAbandonedLoadResult(t *testing.T) {
	ctx := context.Background()
	oldStore := &closeTrackingProvider{}
	lateStore := &closeTrackingProvider{}
	release := make(chan struct{})

	g := &GrypeAdapter{
		store:              oldStore,
		dbStatus:           &vulnerability.ProviderStatus{From: "schema:v6%3Aold"},
		nextUpdateAttempt:  time.Now().Add(-time.Minute),
		stuckUpdateTimeout: 20 * time.Millisecond,
		loadDB: func(distribution.Config, installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			<-release
			return lateStore, &vulnerability.ProviderStatus{From: "schema:v6%3Alate"}, nil
		},
	}

	require.True(t, g.Ready(ctx))
	require.Eventually(t, func() bool {
		g.mu.RLock()
		defer g.mu.RUnlock()
		return !g.updating
	}, 2*time.Second, 5*time.Millisecond)

	g.mu.RLock()
	abandonSchedule := g.nextUpdateAttempt
	g.mu.RUnlock()

	// The abandoned load now returns a perfectly good DB - too late to be trusted.
	close(release)
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&lateStore.closed) == 1
	}, 2*time.Second, 5*time.Millisecond, "a load result that returns after abandonment must be closed")

	g.mu.RLock()
	defer g.mu.RUnlock()
	assert.Same(t, oldStore, g.store, "a discarded late load must not replace the active store")
	assert.Equal(t, int32(0), atomic.LoadInt32(&oldStore.closed), "the active store must not be closed by a discarded late load")
	assert.Equal(t, abandonSchedule, g.nextUpdateAttempt, "a discarded late load must not touch the retry schedule")
}

// Grype's distro types are lowercase slugs compared verbatim, so a configured vendor was
// only trusted when written exactly that way. "Wolfi", or a slug with the whitespace a JSON
// list easily carries, went into the set as a key nothing matches, and adaptive mode quietly
// kept CPE matching on for a vendor the operator had asked it to trust.
func TestBuildTrustedVendorSet_NormalizesSlugs(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		trusted    bool
	}{
		{"canonical", "wolfi", true},
		{"capitalised", "Wolfi", true},
		{"upper case", "WOLFI", true},
		{"leading space", " wolfi", true},
		{"trailing space", "wolfi ", true},
		{"a different vendor", "chainguard", false},
		{"not a distro at all", "not-a-distro", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &GrypeAdapter{
				matchingMode:   config.CVEMatchingAdaptive,
				trustedVendors: buildTrustedVendorSet([]string{tt.configured}),
			}
			// useDefaultMatchers is true exactly when the distro is trusted, which is what
			// turns the CPE matchers off for it.
			assert.Equal(t, tt.trusted, g.resolveUseDefaultMatchers(&distro.Distro{Type: distro.Wolfi}),
				"vendor %q against a wolfi image", tt.configured)
		})
	}
}

// An empty entry is dropped rather than becoming a key that matches a distro with no type.
func TestBuildTrustedVendorSet_SkipsEmpty(t *testing.T) {
	set := buildTrustedVendorSet([]string{"", "   ", "wolfi"})
	assert.Equal(t, map[distro.Type]bool{distro.Wolfi: true}, set)
}

func TestDefaultMatchers_CVEMatchingOffDoesNotProduceCPEMatch(t *testing.T) {
	provider := mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			PackageName: "java_se",
			Constraint: version.MustGetConstraint(
				"< 1.8.0_401",
				version.JVMFormat,
			),
			Reference: vulnerability.Reference{
				ID:        "CVE-DEBUG-CVE-MATCHING-OFF",
				Namespace: "nvd:cpe",
			},
			CPEs: []cpe.CPE{
				cpe.Must(
					"cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
					"",
				),
			},
		},
	)

	packages := []pkg.Package{
		{
			Name:    "java_se",
			Version: "1.8.0_400",
			Type:    syftPkg.BinaryPkg,
			CPEs: []cpe.CPE{
				cpe.Must(
					"cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*",
					"",
				),
			},
		},
	}

	vm := grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              getMatchers(true),
		NormalizeByCVE:        true,
	}

	matches, _, err := vm.FindMatches(packages, pkg.Context{})
	require.NoError(t, err)

	matchCount := 0
	for m := range matches.Enumerate() {
		matchCount++
		for _, detail := range m.Details {
			t.Logf(
				"FOUND: CVE=%s matcher=%s type=%s",
				m.Vulnerability.ID,
				detail.Matcher,
				detail.Type,
			)
		}
	}

	assert.Equal(t, 0, matchCount, "CVEMatchingOff must not produce CPE matches")
}

func TestDefaultMatchers_CVEMatchingOnProducesCPEMatch(t *testing.T) {
	provider := mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			PackageName: "java_se",
			Constraint: version.MustGetConstraint(
				"< 1.8.0_401",
				version.JVMFormat,
			),
			Reference: vulnerability.Reference{
				ID:        "CVE-DEBUG-CVE-MATCHING-ON",
				Namespace: "nvd:cpe",
			},
			CPEs: []cpe.CPE{
				cpe.Must(
					"cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*", ""),
			},
		},
	)

	packages := []pkg.Package{
		{
			Name:    "java_se",
			Version: "1.8.0_400",
			Type:    syftPkg.BinaryPkg,
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*", ""),
			},
		},
	}

	vm := grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              getMatchers(false),
		NormalizeByCVE:        true,
	}

	matches, _, err := vm.FindMatches(packages, pkg.Context{})
	require.NoError(t, err)

	foundCPEMatch := false

	for m := range matches.Enumerate() {
		if m.Vulnerability.ID != "CVE-DEBUG-CVE-MATCHING-ON" {
			continue
		}

		for _, detail := range m.Details {
			if detail.Type == "cpe-match" {
				foundCPEMatch = true
			}
		}
	}

	assert.True(t, foundCPEMatch, "CVEMatchingOn must produce a CPE match for the expected CVE")
}
