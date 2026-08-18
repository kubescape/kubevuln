package registryauth

import (
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialCache_ReusesUnexpiredEntry(t *testing.T) {
	c := newCredentialCache("test")
	var calls int32
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		return &image.RegistryCredentials{Password: "p1"}, time.Now().Add(time.Hour), nil
	}

	first, err := c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	second, err := c.get(context.Background(), "k", fetch)
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "second call should be served from cache")
	assert.Same(t, first, second)
}

func TestCredentialCache_RefetchesAfterExpiry(t *testing.T) {
	c := newCredentialCache("test")
	now := time.Now()
	c.now = func() time.Time { return now }

	var calls int32
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		n := atomic.AddInt32(&calls, 1)
		return &image.RegistryCredentials{Password: string(rune('0' + n))}, now.Add(10 * time.Minute), nil
	}

	_, err := c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))

	// still within the expiry leeway-adjusted window: served from cache
	now = now.Add(5 * time.Minute)
	_, err = c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "still-valid entry should not be refetched")

	// past expiry (minus the 1-minute leeway): must refetch
	now = now.Add(10 * time.Minute)
	_, err = c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "expired entry must be refetched")
}

func TestCredentialCache_DistinctKeysDoNotShareEntries(t *testing.T) {
	c := newCredentialCache("test")
	fetch := func(password string) credentialFetch {
		return func(context.Context) (*image.RegistryCredentials, time.Time, error) {
			return &image.RegistryCredentials{Password: password}, time.Now().Add(time.Hour), nil
		}
	}

	a, err := c.get(context.Background(), "region-a", fetch("a"))
	require.NoError(t, err)
	b, err := c.get(context.Background(), "region-b", fetch("b"))
	require.NoError(t, err)

	assert.Equal(t, "a", a.Password)
	assert.Equal(t, "b", b.Password)
}

func TestCredentialCache_ConcurrentMissesCollapseToOneFetch(t *testing.T) {
	c := newCredentialCache("test")
	const n = 20

	var calls, joined int32
	allJoined := make(chan struct{})
	// onMiss fires synchronously for every caller that reaches a cache miss, before it
	// joins the singleflight group. The cache is never populated until fetch returns (see
	// below), and fetch never returns until every one of the n callers has hit this miss
	// path, so no caller can ever race ahead and be served a cache hit instead of actually
	// contending for the same key -- this is a hard guarantee, not a timing-based one.
	c.onMiss = func() {
		if atomic.AddInt32(&joined, 1) == n {
			close(allJoined)
		}
	}
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		<-allJoined
		return &image.RegistryCredentials{Password: "p"}, time.Now().Add(time.Hour), nil
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := c.get(context.Background(), "k", fetch)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&calls),
		"concurrent callers racing the same cache miss must collapse into a single upstream fetch")
}

func TestCredentialCache_FetchErrorsAreNotCached(t *testing.T) {
	c := newCredentialCache("test")
	boom := errors.New("boom")
	var calls int32
	failThenSucceed := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return nil, time.Time{}, boom
		}
		return &image.RegistryCredentials{Password: "p"}, time.Now().Add(time.Hour), nil
	}

	_, err := c.get(context.Background(), "k", failThenSucceed)
	require.ErrorIs(t, err, boom)

	creds, err := c.get(context.Background(), "k", failThenSucceed)
	require.NoError(t, err)
	assert.Equal(t, "p", creds.Password)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "a failed fetch must not poison the cache for the next call")
}

func TestCredentialCache_ZeroExpiryIsNotCached(t *testing.T) {
	c := newCredentialCache("test")
	var calls int32
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		return &image.RegistryCredentials{Password: "p"}, time.Time{}, nil
	}

	_, err := c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	_, err = c.get(context.Background(), "k", fetch)
	require.NoError(t, err)

	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "a credential with no reported expiry must not be cached")
}

func TestCredentialCache_Reset(t *testing.T) {
	c := newCredentialCache("test")
	var calls int32
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		return &image.RegistryCredentials{Password: "p"}, time.Now().Add(time.Hour), nil
	}

	_, err := c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	c.reset()
	_, err = c.get(context.Background(), "k", fetch)
	require.NoError(t, err)

	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "reset must force the next call to refetch")
}

// Before #750, lookup treated an expired entry as a miss but never removed it, so it sat in
// the cache's backing map forever unless the exact same key happened to be looked up again.
// This asserts the entry is actually gone, not merely shadowed by the expiry check.
func TestCredentialCache_ExpiredEntryIsPurgedNotJustShadowed(t *testing.T) {
	c := newCredentialCache("test")
	now := time.Now()
	c.now = func() time.Time { return now }

	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		return &image.RegistryCredentials{Password: "p"}, now.Add(10 * time.Minute), nil
	}
	_, err := c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	require.Equal(t, 1, c.entries.Len())

	now = now.Add(time.Hour) // well past expiry
	_, ok := c.lookup("k")
	assert.False(t, ok)

	assert.Equal(t, 0, c.entries.Len(),
		"an expired entry must be removed on lookup, not left sitting in the cache")
}

// The cache is keyed by registry host, and that key space is not a small, operator-controlled
// set (see maxCacheEntries' doc comment) -- so without a cap, a burst of distinct keys grows
// the cache without bound. This asserts the cache stays bounded and evicts the
// least-recently-used entry, rather than an arbitrary one, to make room.
func TestCredentialCache_BoundedSizeEvictsLeastRecentlyUsed(t *testing.T) {
	c := newCredentialCache("test")
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		return &image.RegistryCredentials{Password: "p"}, time.Now().Add(time.Hour), nil
	}

	for i := 0; i < maxCacheEntries; i++ {
		_, err := c.get(context.Background(), strconv.Itoa(i), fetch)
		require.NoError(t, err)
	}
	require.Equal(t, maxCacheEntries, c.entries.Len())

	// Key "0" is now the least recently used entry: adding one more distinct key must evict
	// it rather than growing the cache past its cap.
	_, err := c.get(context.Background(), "overflow", fetch)
	require.NoError(t, err)

	assert.Equal(t, maxCacheEntries, c.entries.Len(),
		"cache must stay bounded at its configured capacity")

	var calls int32
	countingFetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		return &image.RegistryCredentials{Password: "p2"}, time.Now().Add(time.Hour), nil
	}
	_, err = c.get(context.Background(), "0", countingFetch)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls),
		"the least-recently-used key must have been evicted to make room, forcing a refetch")
}

// Before mu was reintroduced (review on #753), lookup's read-expiry-then-remove and get's
// re-check-then-add were each a check-then-act sequence spanning two separate, individually
// thread-safe calls into entries -- with nothing making either sequence atomic across
// goroutines. A concurrent refresh's Add for a key could land between another caller's Get
// and Remove for that same key, and get deleted along with the stale entry Remove actually
// meant to evict. This stress-tests that exact interleaving many times over, with both
// operations starting from the same barrier so the scheduler has every opportunity to
// interleave them: a freshly cached credential must never be lost to a concurrent expiry
// check that observed the key before it was refreshed.
func TestCredentialCache_ExpiryRemovalDoesNotRaceConcurrentRefresh(t *testing.T) {
	const iterations = 300

	for i := 0; i < iterations; i++ {
		c := newCredentialCache("test")
		now := time.Now()
		c.now = func() time.Time { return now }

		// Seed an already-expired entry directly: the scenario under test is a caller
		// finding an existing stale entry, not the fetch path that would have created it.
		c.entries.Add("k", cacheEntry{creds: &image.RegistryCredentials{Password: "stale"}, expiry: now.Add(-time.Minute)})

		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			c.lookup("k") // observes "k" expired and removes it
		}()
		go func() {
			defer wg.Done()
			<-start
			_, err := c.get(context.Background(), "k", func(context.Context) (*image.RegistryCredentials, time.Time, error) {
				return &image.RegistryCredentials{Password: "fresh"}, now.Add(time.Hour), nil
			})
			assert.NoError(t, err)
		}()
		close(start)
		wg.Wait()

		creds, ok := c.lookup("k")
		require.True(t, ok, "iteration %d: a freshly cached credential must survive a concurrent expiry-driven removal of the stale entry it replaced", i)
		assert.Equal(t, "fresh", creds.Password, "iteration %d", i)
	}
}

// scrapeMetrics renders the current metric values in Prometheus text format.
func scrapeMetrics(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	require.Equal(t, 200, w.Code)
	return w.Body.String()
}

// The point of collapsing concurrent lookups is to cut upstream credential fetches, so
// result="miss" has to count those fetches. Counting every caller that missed the cache
// instead makes the metric read the same whether the collapsing works or not.
func TestCredentialCache_CoalescedCallersAreNotCountedAsUpstreamFetches(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)
	c := newCredentialCache("ecr")
	const n = 20

	var calls, joined int32
	allJoined := make(chan struct{})
	// Released once every caller has joined the group, not merely reached the miss path: a
	// caller descheduled between the two starts its own execution once the leader is done
	// and is served a cache hit, which is a real outcome but not the one under test here.
	c.onJoined = func() {
		if atomic.AddInt32(&joined, 1) == n {
			close(allJoined)
		}
	}
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		<-allJoined
		return &image.RegistryCredentials{Password: "p"}, time.Now().Add(time.Hour), nil
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := c.get(context.Background(), "k", fetch)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), atomic.LoadInt32(&calls))

	body := scrapeMetrics(t, m)
	assert.Contains(t, body, `kubevuln_registry_auth_cache_total{result="miss",strategy="ecr"} 1`,
		"one upstream fetch must be one miss, not one per caller")
	assert.Contains(t, body, `kubevuln_registry_auth_cache_total{result="coalesced",strategy="ecr"} 19`,
		"callers served by another caller's in-flight fetch cost no upstream request")

	// A later lookup is served from the entry the shared fetch cached.
	_, err = c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	assert.Contains(t, scrapeMetrics(t, m), `kubevuln_registry_auth_cache_total{result="hit",strategy="ecr"} 1`)
}

// The re-check inside the singleflight closure is a cache read like any other, so it counts
// as a hit. Recording it where the caller is served, rather than inside the closure, keeps
// it consistent with the other two: a caller that never gets its result records nothing.
func TestCredentialCache_RecheckInsideSingleflightRecordsHit(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)
	c := newCredentialCache("ecr")

	// onMiss fires after the first lookup misses and before this caller joins the group,
	// which is exactly the window in which another caller can populate the cache, and the
	// only way the closure's re-check ever finds anything.
	c.onMiss = func() {
		c.entries.Add("k", cacheEntry{creds: &image.RegistryCredentials{Password: "p"}, expiry: time.Now().Add(time.Hour)})
	}
	var calls int32
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		return &image.RegistryCredentials{Password: "other"}, time.Now().Add(time.Hour), nil
	}

	creds, err := c.get(context.Background(), "k", fetch)
	require.NoError(t, err)
	assert.Equal(t, "p", creds.Password)
	assert.Zero(t, atomic.LoadInt32(&calls), "the re-check found it, so nothing was fetched")

	body := scrapeMetrics(t, m)
	assert.Contains(t, body, `kubevuln_registry_auth_cache_total{result="hit",strategy="ecr"} 1`)
	assert.NotContains(t, body, `result="miss"`)
	assert.NotContains(t, body, `result="coalesced"`)
}

// A caller that gives up has no lookup outcome to report, and recording one made abandoned
// waits indistinguishable from fetches.
func TestCredentialCache_AbandonedCallerRecordsNoOutcome(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)
	c := newCredentialCache("ecr")

	release := make(chan struct{})
	defer close(release)
	started := make(chan struct{})
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		close(started)
		<-release
		return &image.RegistryCredentials{Password: "p"}, time.Now().Add(time.Hour), nil
	}

	// The leader holds the key while a second caller waits on it, then gives up.
	go func() { _, _ = c.get(context.Background(), "k", fetch) }()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.get(ctx, "k", fetch)
	require.ErrorIs(t, err, context.Canceled)

	body := scrapeMetrics(t, m)
	assert.NotContains(t, body, `result="coalesced"`,
		"a caller that abandoned its wait was never served")
	assert.Contains(t, body, `kubevuln_registry_auth_cache_total{result="miss",strategy="ecr"} 1`,
		"the only miss is the in-flight fetch, not the caller that walked away from it")
}
