package controllers

import (
	"sync"
	"time"

	"github.com/kubescape/kubevuln/core/domain"
)

type scanStatusStore struct {
	mu    sync.RWMutex
	items map[string]domain.ScanStatus
}

func newScanStatusStore() *scanStatusStore {
	return &scanStatusStore{items: make(map[string]domain.ScanStatus)}
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
}

func (s *scanStatusStore) markRunning(jobID string) {
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
	status.State = domain.ScanStateRunning
	if status.Phase == "" || status.Phase == string(domain.ScanStateQueued) {
		status.Phase = string(domain.ScanStateRunning)
	}
	if status.StartedAt.IsZero() {
		status.StartedAt = now
	}
	status.UpdatedAt = now
	s.items[jobID] = status
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
	if status.State == domain.ScanStateSucceeded || status.State == domain.ScanStateFailed || status.State == domain.ScanStateAbandoned {
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
		status.FinishedAt = now
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
	status.State = state
	status.Phase = "completed"
	status.Reason = reason
	if status.StartedAt.IsZero() {
		status.StartedAt = now
	}
	status.FinishedAt = now
	status.UpdatedAt = now
	s.items[jobID] = status
}

func (s *scanStatusStore) get(jobID string) (domain.ScanStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status, ok := s.items[jobID]
	return status, ok
}
