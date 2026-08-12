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
