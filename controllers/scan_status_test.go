package controllers

import (
	"fmt"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/require"
)

func TestScanStatusStore_EvictsExpiredTerminalEntries(t *testing.T) {
	s := newScanStatusStore()
	s.ttl = time.Millisecond

	s.recordAccepted("stale", "generateSBOM")
	s.markSucceeded("stale")

	// Backdate FinishedAt directly so eviction has something to expire, since
	// markSucceeded stamps it with time.Now() and the TTL is tiny.
	s.mu.Lock()
	stale := s.items["stale"]
	finishedAt := time.Now().UTC().Add(-time.Hour)
	stale.FinishedAt = &finishedAt
	s.items["stale"] = stale
	s.mu.Unlock()

	// A queued (non-terminal) job must survive eviction regardless of age.
	s.recordAccepted("active", "generateSBOM")
	s.mu.Lock()
	active := s.items["active"]
	active.AcceptedAt = time.Now().UTC().Add(-time.Hour)
	active.UpdatedAt = active.AcceptedAt
	s.items["active"] = active
	s.mu.Unlock()

	// Trigger eviction via recordAccepted's lazy sweep.
	s.recordAccepted("new", "generateSBOM")

	_, ok := s.get("stale")
	require.False(t, ok, "expired terminal entry should have been evicted")

	_, ok = s.get("active")
	require.True(t, ok, "non-terminal entry must never be evicted regardless of age")

	_, ok = s.get("new")
	require.True(t, ok)
}

func TestScanStatusStore_GetEvictsExpiredTerminalEntries(t *testing.T) {
	s := newScanStatusStore()
	s.ttl = time.Millisecond

	s.recordAccepted("stale", "generateSBOM")
	s.markSucceeded("stale")

	s.mu.Lock()
	stale := s.items["stale"]
	finishedAt := time.Now().UTC().Add(-time.Hour)
	stale.FinishedAt = &finishedAt
	s.items["stale"] = stale
	s.mu.Unlock()

	_, ok := s.get("stale")
	require.False(t, ok, "expired terminal entry should not be returned on lookup")
}

func TestScanStatusStore_EvictsOldestTerminalEntriesOverCap(t *testing.T) {
	s := newScanStatusStore()
	s.maxEntries = 3

	for i := 0; i < 3; i++ {
		jobID := fmt.Sprintf("job-%d", i)
		s.recordAccepted(jobID, "generateSBOM")
		s.markSucceeded(jobID)
		s.mu.Lock()
		st := s.items[jobID]
		finishedAt := time.Now().UTC().Add(time.Duration(i) * time.Second)
		st.FinishedAt = &finishedAt
		s.items[jobID] = st
		s.mu.Unlock()
	}

	require.Len(t, s.items, 3)

	// Adding a 4th entry pushes the store over cap; the oldest terminal
	// record (job-0) must be evicted to make room.
	s.recordAccepted("job-3", "generateSBOM")

	s.mu.RLock()
	count := len(s.items)
	s.mu.RUnlock()
	require.LessOrEqual(t, count, s.maxEntries+1, "store must not grow unbounded past the cap")

	_, ok := s.get("job-0")
	require.False(t, ok, "oldest terminal entry should have been evicted to satisfy the cap")

	_, ok = s.get("job-3")
	require.True(t, ok, "newly accepted job must be retained")
}

// Before #790, get() ran evictLocked's full-store sweep on every call, so a lookup for one
// jobID paid for evaluating every other entry in the store too. This proves get() no longer
// does that: stale, unrelated terminal entries elsewhere in the store must survive a get()
// call for a different key, since only a write path (recordAccepted/markTerminal) or a get()
// for that specific key is what evicts them now.
func TestScanStatusStore_GetDoesNotEvictUnrelatedStaleEntries(t *testing.T) {
	s := newScanStatusStore()
	s.ttl = time.Millisecond

	s.recordAccepted("stale-1", "generateSBOM")
	s.markSucceeded("stale-1")
	s.recordAccepted("stale-2", "generateSBOM")
	s.markSucceeded("stale-2")

	// Backdate both past the TTL directly, bypassing the eviction that recordAccepted and
	// markSucceeded already ran while their own FinishedAt was still fresh.
	s.mu.Lock()
	longAgo := time.Now().UTC().Add(-time.Hour)
	for _, jobID := range []string{"stale-1", "stale-2"} {
		st := s.items[jobID]
		st.FinishedAt = &longAgo
		s.items[jobID] = st
	}
	s.mu.Unlock()

	// A get() for an unrelated, non-existent key must not sweep the store.
	_, ok := s.get("unrelated")
	require.False(t, ok)

	s.mu.RLock()
	_, stale1Present := s.items["stale-1"]
	_, stale2Present := s.items["stale-2"]
	s.mu.RUnlock()
	require.True(t, stale1Present, "get() for a different key must not evict unrelated stale entries")
	require.True(t, stale2Present, "get() for a different key must not evict unrelated stale entries")
}

// get() must still refuse to hand back a terminal entry whose TTL has elapsed, and must
// evict exactly the key it was asked about -- not the whole store -- when it finds one.
func TestScanStatusStore_GetEvictsOnlyTheRequestedStaleKey(t *testing.T) {
	s := newScanStatusStore()
	s.ttl = time.Millisecond

	s.recordAccepted("stale", "generateSBOM")
	s.markSucceeded("stale")
	s.recordAccepted("other-stale", "generateSBOM")
	s.markSucceeded("other-stale")

	s.mu.Lock()
	longAgo := time.Now().UTC().Add(-time.Hour)
	for _, jobID := range []string{"stale", "other-stale"} {
		st := s.items[jobID]
		st.FinishedAt = &longAgo
		s.items[jobID] = st
	}
	s.mu.Unlock()

	_, ok := s.get("stale")
	require.False(t, ok, "expired terminal entry must not be returned")

	s.mu.RLock()
	_, stalePresent := s.items["stale"]
	_, otherPresent := s.items["other-stale"]
	s.mu.RUnlock()
	require.False(t, stalePresent, "get() must evict the specific expired key it was asked about")
	require.True(t, otherPresent, "get() must not evict unrelated expired entries it wasn't asked about")
}

func TestScanStatusStore_MarkRunningOnlyClaimsQueuedJobs(t *testing.T) {
	s := newScanStatusStore()
	s.recordAccepted("job", "generateSBOM")
	s.markAbandonedQueued(domain.ScanReasonShutdownAbandoned)

	status, ok := s.get("job")
	require.True(t, ok)
	require.Equal(t, domain.ScanStateAbandoned, status.State)

	// A worker racing shutdown must not revive an abandoned job back to running.
	require.False(t, s.markRunning("job"))

	status, ok = s.get("job")
	require.True(t, ok)
	require.Equal(t, domain.ScanStateAbandoned, status.State, "abandoned state must remain terminal")

	s.markSucceeded("job")
	status, ok = s.get("job")
	require.True(t, ok)
	require.Equal(t, domain.ScanStateAbandoned, status.State, "terminal jobs must reject later success writes")

	s.markFailed("job", "unexpected_error")
	status, ok = s.get("job")
	require.True(t, ok)
	require.Equal(t, domain.ScanStateAbandoned, status.State, "terminal jobs must reject later failure writes")
}

// TestScanStatusStore_RecordAcceptedRejectsActiveJobID is the regression test for #856:
// reusing a jobID while its prior job is still queued or running must not silently reset
// that job's tracking record. Before the fix, a second recordAccepted for the same jobID
// always overwrote the first, letting a second closure claim the same jobID via markRunning
// and then race the first job's own markTerminal call for which outcome the shared record
// keeps -- silently dropping whichever one lost the race.
func TestScanStatusStore_RecordAcceptedRejectsActiveJobID(t *testing.T) {
	s := newScanStatusStore()

	require.True(t, s.recordAccepted("job", "generateSBOM"), "first admission for a fresh jobID must succeed")
	require.False(t, s.recordAccepted("job", "generateSBOM"), "reusing a queued jobID must be rejected")

	status, ok := s.get("job")
	require.True(t, ok)
	require.Equal(t, domain.ScanStateQueued, status.State, "the rejected re-admission must not have touched the record")

	require.True(t, s.markRunning("job"))
	require.False(t, s.recordAccepted("job", "generateSBOM"), "reusing a running jobID must be rejected")

	status, ok = s.get("job")
	require.True(t, ok)
	require.Equal(t, domain.ScanStateRunning, status.State, "the rejected re-admission must not have reset a running job back to queued")
	require.NotNil(t, status.StartedAt, "the rejected re-admission must not have discarded StartedAt")

	// The original job's own outcome must survive exactly as if the duplicate admission had
	// never been attempted.
	s.markFailed("job", "unexpected_error")
	status, ok = s.get("job")
	require.True(t, ok)
	require.Equal(t, domain.ScanStateFailed, status.State)
	require.Equal(t, "unexpected_error", status.Reason)
}

// TestScanStatusStore_RecordAcceptedAllowsReuseOnceTerminal proves the fix is narrowly
// scoped: reusing a jobID is only rejected while the prior job under that ID is still
// active. Once it has reached any terminal state, reuse must keep working exactly as
// before -- this is the ordinary, benign case of a caller reusing an ID once its
// predecessor is done.
func TestScanStatusStore_RecordAcceptedAllowsReuseOnceTerminal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reach func(s *scanStatusStore, jobID string)
	}{
		{"succeeded", func(s *scanStatusStore, jobID string) { s.markSucceeded(jobID) }},
		{"failed", func(s *scanStatusStore, jobID string) { s.markFailed(jobID, "some_reason") }},
		{"abandoned", func(s *scanStatusStore, jobID string) { s.markAbandoned(jobID, domain.ScanReasonShutdownAbandoned) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newScanStatusStore()
			require.True(t, s.recordAccepted("job", "generateSBOM"))
			tc.reach(s, "job")

			require.True(t, s.recordAccepted("job", "generateSBOM"), "reusing a jobID whose prior job is terminal must be accepted")

			status, ok := s.get("job")
			require.True(t, ok)
			require.Equal(t, domain.ScanStateQueued, status.State, "the record must reset to a fresh queued job")
			require.Nil(t, status.StartedAt, "the fresh record must not carry over the prior job's StartedAt")
		})
	}
}

// Before #790, get()'s cost scaled with the store's total size (evictLocked's full sweep).
// This benchmark's ns/op should stay flat across store sizes now that a lookup only touches
// the one key it was asked for; run with -benchtime and compare sizes to see the effect, e.g.
// go test ./controllers/ -run '^$' -bench BenchmarkScanStatusStore_Get -benchtime=200000x
func BenchmarkScanStatusStore_Get(b *testing.B) {
	for _, size := range []int{100, 10000} {
		b.Run(fmt.Sprintf("storeSize=%d", size), func(b *testing.B) {
			s := newScanStatusStore()
			for i := 0; i < size; i++ {
				jobID := fmt.Sprintf("job-%d", i)
				s.recordAccepted(jobID, "generateSBOM")
				s.markSucceeded(jobID)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.get("job-0")
			}
		})
	}
}
