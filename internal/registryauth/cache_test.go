package registryauth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
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
	var calls, started int32
	release := make(chan struct{})
	fetch := func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		<-release // hold the leader here until every caller has actually joined the race
		return &image.RegistryCredentials{Password: "p"}, time.Now().Add(time.Hour), nil
	}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			atomic.AddInt32(&started, 1)
			_, err := c.get(context.Background(), "k", fetch)
			assert.NoError(t, err)
		}()
	}

	// Don't release the leader's fetch until every goroutine has actually called get():
	// releasing too early risks the leader finishing and populating the cache before the
	// rest even started, which would let a non-coalescing implementation (one that calls
	// fetch on every miss instead of deduping) pass by accident.
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&started) == n
	}, 2*time.Second, time.Millisecond)
	// "started" only means each goroutine's call to get() has begun, not that it has
	// reached the blocking point inside singleflight yet -- give the scheduler a moment to
	// actually land every one of them there before letting the leader's fetch return.
	time.Sleep(100 * time.Millisecond)
	close(release)
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
