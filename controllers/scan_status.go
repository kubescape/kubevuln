package controllers

import (
	"container/heap"
	"slices"
	"sync"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
)

// defaultScanStatusTTL bounds how long a terminal (succeeded/failed/abandoned) record
// is retained after it finished, and defaultScanStatusMaxEntries caps the total number
// of records regardless of age. Without both, scanStatusStore.items would grow without
// bound over the lifetime of a long-running kubevuln pod.
const (
	defaultScanStatusTTL        = time.Hour
	defaultScanStatusMaxEntries = 10000
)

type scanStatusStore struct {
	mu         sync.RWMutex
	items      map[string]domain.ScanStatus
	ttl        time.Duration
	maxEntries int
}

type candidate struct {
	jobID      string
	finishedAt time.Time
}

func newScanStatusStore() *scanStatusStore {
	return &scanStatusStore{
		items:      make(map[string]domain.ScanStatus),
		ttl:        defaultScanStatusTTL,
		maxEntries: defaultScanStatusMaxEntries,
	}
}

// expiredTerminal reports whether status is a terminal record whose TTL has elapsed as of
// now. Used both by evictLocked's full-store sweep and by get's single-key check.
func expiredTerminal(status domain.ScanStatus, now time.Time, ttl time.Duration) bool {
	return isTerminal(status.State) && status.FinishedAt != nil && now.Sub(*status.FinishedAt) > ttl
}

// evictLocked removes terminal records older than s.ttl, then, if still over
// s.maxEntries, removes the oldest terminal records until the cap is met. Active
// (queued/running) records are never evicted. Callers must hold s.mu for writing.
func (s *scanStatusStore) evictLocked(now time.Time) {
	for jobID, status := range s.items {
		if expiredTerminal(status, now, s.ttl) {
			delete(s.items, jobID)
		}
	}

	overflow := len(s.items) - s.maxEntries
	if overflow <= 0 {
		return
	}

	selected := make(candidateHeap, 0, overflow)
	for jobID, status := range s.items {
		if !isTerminal(status.State) || status.FinishedAt == nil {
			continue
		}
		cand := candidate{jobID: jobID, finishedAt: *status.FinishedAt}
		if len(selected) < overflow {
			heap.Push(&selected, cand)
			continue
		}
		if cand.finishedAt.Before(selected[0].finishedAt) {
			selected[0] = cand
			heap.Fix(&selected, 0)
		}
	}
	slices.SortFunc([]candidate(selected), func(a, b candidate) int {
		return a.finishedAt.Compare(b.finishedAt)
	})
	for _, cand := range selected {
		delete(s.items, cand.jobID)
	}
}

type candidateHeap []candidate

func (h candidateHeap) Len() int { return len(h) }

func (h candidateHeap) Less(i, j int) bool {
	return h[i].finishedAt.After(h[j].finishedAt)
}

func (h candidateHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *candidateHeap) Push(x any) {
	*h = append(*h, x.(candidate))
}

func (h *candidateHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func isTerminal(state domain.ScanState) bool {
	return state == domain.ScanStateSucceeded || state == domain.ScanStateFailed || state == domain.ScanStateAbandoned
}

func (s *scanStatusStore) recordAccepted(jobID, endpoint string) {
	if jobID == "" {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[jobID] = domain.ScanStatus{
		JobID:      jobID,
		Endpoint:   endpoint,
		State:      domain.ScanStateQueued,
		Phase:      string(domain.ScanStateQueued),
		AcceptedAt: now,
		UpdatedAt:  now,
	}
	s.evictLocked(now)
}

func (s *scanStatusStore) markRunning(jobID string) bool {
	if jobID == "" {
		return false
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.items[jobID]
	if !ok || status.State != domain.ScanStateQueued {
		return false
	}
	status.State = domain.ScanStateRunning
	if status.Phase == "" || status.Phase == string(domain.ScanStateQueued) {
		status.Phase = string(domain.ScanStateRunning)
	}
	if status.StartedAt == nil {
		startedAt := now
		status.StartedAt = &startedAt
	}
	status.UpdatedAt = now
	s.items[jobID] = status
	return true
}

func (s *scanStatusStore) markPhase(jobID, phase string) {
	if jobID == "" || phase == "" {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.items[jobID]
	if !ok {
		return
	}
	if isTerminal(status.State) {
		return
	}
	status.Phase = phase
	status.UpdatedAt = now
	s.items[jobID] = status
}

func (s *scanStatusStore) markSucceeded(jobID string) {
	s.markTerminal(jobID, domain.ScanStateSucceeded, "")
}

func (s *scanStatusStore) markFailed(jobID, reason string) {
	s.markTerminal(jobID, domain.ScanStateFailed, reason)
}

// markAbandoned marks a single job abandoned, the same terminal state markAbandonedQueued
// gives every job still queued when Shutdown starts. It exists for a job that reaches
// submit() after shuttingDown is already set (see HTTPController.submit): markAbandonedQueued's
// one-time sweep runs before that job is necessarily even in the store yet, so this is what
// keeps it from being left stuck "accepted" forever instead. A no-op if the job is already
// terminal, so calling this after the sweep already caught the same jobID is harmless.
func (s *scanStatusStore) markAbandoned(jobID, reason string) {
	s.markTerminal(jobID, domain.ScanStateAbandoned, reason)
}

func (s *scanStatusStore) markAbandonedQueued(reason string) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for jobID, status := range s.items {
		if status.State != domain.ScanStateQueued {
			continue
		}
		status.State = domain.ScanStateAbandoned
		status.Phase = string(domain.ScanStateAbandoned)
		status.Reason = reason
		finishedAt := now
		status.FinishedAt = &finishedAt
		status.UpdatedAt = now
		s.items[jobID] = status
	}
}

func (s *scanStatusStore) markTerminal(jobID string, state domain.ScanState, reason string) {
	if jobID == "" {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.items[jobID]
	if !ok {
		return
	}
	if isTerminal(status.State) {
		return
	}
	status.State = state
	status.Phase = "completed"
	if state == domain.ScanStateAbandoned {
		// Match markAbandonedQueued's convention for the same terminal state, instead of
		// the generic "completed" every other terminal state gets here.
		status.Phase = string(domain.ScanStateAbandoned)
	}
	status.Reason = reason
	if status.StartedAt == nil {
		startedAt := now
		status.StartedAt = &startedAt
	}
	finishedAt := now
	status.FinishedAt = &finishedAt
	status.UpdatedAt = now
	s.items[jobID] = status
	s.evictLocked(now)
}

// get looks up jobID without paying for evictLocked's full-store sweep: recordAccepted and
// markTerminal already run it on every write, so the store is kept bounded and mostly fresh
// without a read needing to do that work too (see #790). The one thing a read still owes on
// its own is not handing back a terminal record whose TTL has elapsed but that no write has
// evicted yet -- expiredTerminal is the same check evictLocked uses, applied to just this one
// entry instead of every entry in the store.
func (s *scanStatusStore) get(jobID string) (domain.ScanStatus, bool) {
	s.mu.RLock()
	status, ok := s.items[jobID]
	s.mu.RUnlock()
	if !ok {
		return domain.ScanStatus{}, false
	}
	now := time.Now().UTC()
	if !expiredTerminal(status, now, s.ttl) {
		return status, true
	}

	// Evict just this key: re-check under the write lock in case a concurrent write
	// already removed or changed it between the RUnlock above and here.
	s.mu.Lock()
	if cur, ok := s.items[jobID]; ok && expiredTerminal(cur, now, s.ttl) {
		delete(s.items, jobID)
	}
	s.mu.Unlock()
	return domain.ScanStatus{}, false
}
