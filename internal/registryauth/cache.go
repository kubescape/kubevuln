package registryauth

import (
	"context"
	"sync"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/kubescape/kubevuln/internal/metrics"
	"golang.org/x/sync/singleflight"
)

// expiryLeeway is subtracted from a credential's reported expiry, so a token that's about
// to expire mid-scan is refreshed proactively instead of being handed out and failing the
// pull moments later.
const expiryLeeway = 1 * time.Minute

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
	mu       sync.Mutex
	entries  map[string]cacheEntry
	group    singleflight.Group
	strategy string
	// now is overridable in tests so expiry can be exercised without a real time.Sleep.
	now func() time.Time
}

type cacheEntry struct {
	creds  *image.RegistryCredentials
	expiry time.Time
}

func newCredentialCache(strategy string) *credentialCache {
	return &credentialCache{entries: map[string]cacheEntry{}, strategy: strategy, now: time.Now}
}

// get returns a cached, still-valid credential for key if one exists, otherwise calls
// fetch -- deduplicated across concurrent callers racing the same key via singleflight --
// and caches the result when fetch reports a non-zero expiry. Fetch errors are never
// cached: a transient failure (e.g. a momentary STS/ADC hiccup) must not poison the cache
// for other callers or the next scan.
func (c *credentialCache) get(ctx context.Context, key string, fetch credentialFetch) (*image.RegistryCredentials, error) {
	if creds, ok := c.lookup(key); ok {
		metrics.RecordRegistryAuthCache(ctx, c.strategy, metrics.RegistryAuthCacheHit)
		return creds, nil
	}

	v, err, _ := c.group.Do(key, func() (interface{}, error) {
		// Re-check under the singleflight key: a caller that lost the race to become the
		// leader for this key may have been given a result already cached by the winner
		// of an earlier, now-resolved Do call for the same key.
		if creds, ok := c.lookup(key); ok {
			return creds, nil
		}
		creds, expiry, ferr := fetch(ctx)
		if ferr != nil {
			return nil, ferr
		}
		if !expiry.IsZero() {
			c.mu.Lock()
			c.entries[key] = cacheEntry{creds: creds, expiry: expiry.Add(-expiryLeeway)}
			c.mu.Unlock()
		}
		return creds, nil
	})
	if err != nil {
		metrics.RecordRegistryAuthCache(ctx, c.strategy, metrics.RegistryAuthCacheMiss)
		return nil, err
	}
	metrics.RecordRegistryAuthCache(ctx, c.strategy, metrics.RegistryAuthCacheMiss)
	return v.(*image.RegistryCredentials), nil
}

func (c *credentialCache) lookup(key string) (*image.RegistryCredentials, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || !c.now().Before(entry.expiry) {
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
	c.entries = map[string]cacheEntry{}
}
