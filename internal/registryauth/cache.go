package registryauth

import (
	"context"
	"sync"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/kubescape/kubevuln/internal/metrics"
	"golang.org/x/sync/singleflight"
)

// expiryLeeway is subtracted from a credential's reported expiry, so a token that's about
// to expire mid-scan is refreshed proactively instead of being handed out and failing the
// pull moments later.
const expiryLeeway = 1 * time.Minute

// fetchTimeout bounds a single upstream credential fetch, independent of any one caller's
// context. The fetch runs once per singleflight key and is shared by every concurrent
// caller racing that key, so it must not be tied to whichever caller happened to become
// the leader: that caller's context canceling must not abort the fetch -- and therefore
// the result -- for every other caller still waiting on it.
const fetchTimeout = 30 * time.Second

// maxCacheEntries bounds a credentialCache's size. The cache is keyed by registry host
// (registryauth.go), and that key space is not a small, operator-controlled set: an ECR
// hostname embeds a 12-digit account ID and region, and a GCR/Artifact Registry hostname is
// only pattern-matched, not looked up against a known list. Both are read straight out of a
// scanned workload's image reference, so without a cap, a fleet with many distinct
// registries -- or a workload able to set its own image reference -- can grow the cache
// without bound for the life of the process. Bounding it with an LRU also means an entry
// that's never looked up again after it expires doesn't sit in the map forever: it ages out
// under normal turnover instead of only being removed by the lazy check in lookup. See #750.
const maxCacheEntries = 1024

// credentialFetch is a provider's underlying fetch: it returns credentials plus the time
// they stop being valid. A zero expiry means "no reported expiry" -- the credential is
// still returned, but not cached, since there's nothing to bound the cache entry's
// lifetime by.
type credentialFetch func(ctx context.Context) (*image.RegistryCredentials, time.Time, error)

// credentialCache reuses a fetched credential until its provider-reported expiry, and
// collapses concurrent callers racing a cache miss for the same key into a single upstream
// fetch. Without this, every scan of a private image independently re-fetches credentials
// -- an ECR authorization token is valid for 12 hours, yet was being re-requested on every
// single scan -- and a burst of concurrently running scans against the same registry (the
// HTTP controller's worker pool runs many scans in parallel) each fired their own upstream
// request, risking cloud provider rate limiting. See #569.
type credentialCache struct {
	// mu guards the compound operations below, not individual entries calls: lru.Cache is
	// already safe for a single Get/Add/Remove call on its own, but lookup's
	// read-expiry-then-remove and get's re-check-then-add are each a check-then-act
	// sequence across two separate calls into it, and lru.Cache exposes no compare-and-
	// delete or compare-and-add to make either one atomic by itself. Without mu, one
	// goroutine's expiry-driven Remove can race a concurrent refresh's Add for the same
	// key and delete the fresh entry the refresh just cached instead of the stale one it
	// observed. See #753 review.
	mu       sync.Mutex
	entries  *lru.Cache[string, cacheEntry]
	group    singleflight.Group
	strategy string
	// now is overridable in tests so expiry can be exercised without a real time.Sleep.
	now func() time.Time
	// onMiss, if set, is called synchronously by every caller that reaches a cache miss,
	// before it joins the singleflight group. Tests use it as a deterministic barrier to
	// prove real concurrent contention on a miss, instead of a timing-based sleep.
	onMiss func()
	// onJoined, if set, is called synchronously by every caller once it has joined the
	// singleflight group for a key. This is the one moment onMiss cannot express: onMiss
	// fires just before DoChan, so a caller can still be descheduled in between, miss the
	// in-flight execution entirely and start a fresh one that re-checks straight into a
	// cache hit. Tests that need every caller provably waiting on the same fetch release
	// the leader from here instead.
	onJoined func()
}

type cacheEntry struct {
	creds  *image.RegistryCredentials
	expiry time.Time
}

func newCredentialCache(strategy string) *credentialCache {
	entries, err := lru.New[string, cacheEntry](maxCacheEntries)
	if err != nil {
		// lru.New only errors when size <= 0, and maxCacheEntries is a positive constant.
		panic(err)
	}
	return &credentialCache{entries: entries, strategy: strategy, now: time.Now}
}

// get returns a cached, still-valid credential for key if one exists, otherwise calls
// fetch -- deduplicated across concurrent callers racing the same key via singleflight --
// and caches the result when fetch reports a non-zero expiry. Fetch errors are never
// cached: a transient failure (e.g. a momentary STS/ADC hiccup) must not poison the cache
// for other callers or the next scan.
//
// The shared fetch runs under its own fetchTimeout-bounded context, not ctx: singleflight
// hands the leader's result to every caller waiting on the same key, so running the fetch
// under one specific caller's ctx would fail every other caller the instant that one
// caller's context was canceled. Each caller instead races the shared result against its
// own ctx via DoChan, so a caller can give up on its own terms without affecting the
// fetch (which keeps running, and still populates the cache for whoever asks next) or any
// other waiting caller.
func (c *credentialCache) get(ctx context.Context, key string, fetch credentialFetch) (*image.RegistryCredentials, error) {
	if creds, ok := c.lookup(key); ok {
		metrics.RecordRegistryAuthCache(ctx, c.strategy, metrics.RegistryAuthCacheHit)
		return creds, nil
	}
	if c.onMiss != nil {
		c.onMiss()
	}

	// pending is the outcome this caller still owes once it is actually served. It stays
	// coalesced unless this caller's own closure runs, since exactly one caller's closure
	// runs per key and the rest are served by it at no upstream cost. It is cleared when the
	// closure fetches, because a fetch is counted there instead: one upstream call has to be
	// one miss whether or not this caller sticks around for it.
	//
	// Only read in the ch branch below, where receiving from ch happens-after the closure
	// returns. Reading it on the ctx.Done() path would race with the closure still running.
	pending := metrics.RegistryAuthCacheCoalesced
	ch := c.group.DoChan(key, func() (interface{}, error) {
		// Re-check under the singleflight key: a caller that lost the race to become the
		// leader for this key may have been given a result already cached by the winner
		// of an earlier, now-resolved Do call for the same key.
		if creds, ok := c.lookup(key); ok {
			pending = metrics.RegistryAuthCacheHit
			return creds, nil
		}
		pending = ""
		metrics.RecordRegistryAuthCache(ctx, c.strategy, metrics.RegistryAuthCacheMiss)
		fetchCtx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
		defer cancel()
		creds, expiry, ferr := fetch(fetchCtx)
		if ferr != nil {
			return nil, ferr
		}
		if !expiry.IsZero() {
			c.mu.Lock()
			c.entries.Add(key, cacheEntry{creds: creds, expiry: expiry.Add(-expiryLeeway)})
			c.mu.Unlock()
		}
		return creds, nil
	})
	if c.onJoined != nil {
		c.onJoined()
	}

	select {
	case <-ctx.Done():
		// Nothing to record: this caller gave up before its lookup resolved either way. The
		// fetch it was waiting on is unaffected and reports its own outcome when it lands.
		return nil, ctx.Err()
	case res := <-ch:
		if pending != "" {
			metrics.RecordRegistryAuthCache(ctx, c.strategy, pending)
		}
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*image.RegistryCredentials), nil
	}
}

func (c *credentialCache) lookup(key string) (*image.RegistryCredentials, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries.Get(key)
	if !ok {
		return nil, false
	}
	if !c.now().Before(entry.expiry) {
		// Remove it now instead of leaving it for the LRU to evict on its own schedule: a
		// key that's looked up once and never again would otherwise sit in the cache,
		// still occupying a slot, until capacity eventually forced it out. Removing it
		// under the same mu critical section as the Get/expiry-check above -- rather than
		// as a separate, later call -- is what keeps this atomic: a concurrent refresh's
		// Add for this key can only happen entirely before this section starts or entirely
		// after it ends, never in the middle of it.
		c.entries.Remove(key)
		return nil, false
	}
	return entry.creds, true
}

// reset clears all cached entries. Used by tests that override GCPCredsFn/ECRCredsFn and
// need the next Credentials() call to actually reach the override instead of a value
// cached by an earlier test.
func (c *credentialCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries.Purge()
}
