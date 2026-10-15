package controllers

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
)

type inventoryTimer interface{ Stop() bool }
type hostInventoryRetryPolicy struct {
	now         func() time.Time
	afterFunc   func(time.Duration, func()) inventoryTimer
	jitter      func(time.Duration) time.Duration
	maxAttempts int
	maxAge      time.Duration
}

func defaultHostInventoryRetryPolicy() *hostInventoryRetryPolicy {
	return &hostInventoryRetryPolicy{
		now:         time.Now,
		afterFunc:   func(d time.Duration, f func()) inventoryTimer { return time.AfterFunc(d, f) },
		jitter:      func(d time.Duration) time.Duration { return time.Duration(float64(d) * (0.8 + rand.Float64()*0.4)) },
		maxAttempts: 20, maxAge: 15 * time.Minute,
	}
}

// Each allocation is an internal generation token, independent of the public job ID.
// hostRetryMu serializes acceptance, expiry, callbacks and terminal ownership.
type hostInventoryJob struct {
	h                         *HTTPController
	ctx                       context.Context
	jobID                     string
	details                   []helpers.IDetails
	policy                    *hostInventoryRetryPolicy
	start                     time.Time
	attempts                  int
	active                    bool
	queued                    bool
	inventoryResolved         bool
	expired                   bool
	terminal                  bool
	abandoned                 bool
	deadline                  time.Time
	delayTimer, deadlineTimer inventoryTimer
	cancel                    context.CancelFunc
	reportFailure             func(context.Context, error)
}

func (h *HTTPController) runCPScan(ctx context.Context, jobID string, details ...helpers.IDetails) {
	h.hostRetryMu.Lock()
	if h.hostRetryPolicy == nil {
		h.hostRetryPolicy = defaultHostInventoryRetryPolicy()
	}
	j := &hostInventoryJob{h: h, ctx: ctx, jobID: jobID, details: details, policy: h.hostRetryPolicy, queued: true}
	if h.hostRetries == nil {
		h.hostRetries = make(map[*hostInventoryJob]struct{})
	}
	h.hostRetries[j] = struct{}{}
	if h.hostRetryClosed {
		j.abandoned = true
		j.finishLocked(nil)
		h.hostRetryMu.Unlock()
		return
	}
	h.hostRetryMu.Unlock()
	j.submit()
}

func (j *hostInventoryJob) submit() {
	if !j.h.submit(j.run) {
		j.h.hostRetryMu.Lock()
		if !j.terminal {
			j.abandoned = true
			j.finishLocked(nil)
		}
		j.h.hostRetryMu.Unlock()
	}
}

func (j *hostInventoryJob) pastDeadlineLocked() bool {
	return !j.inventoryResolved && !j.deadline.IsZero() && !j.policy.now().Before(j.deadline)
}

func (j *hostInventoryJob) run() {
	h := j.h
	h.hostRetryMu.Lock()
	if j.terminal || !j.queued || j.active {
		h.hostRetryMu.Unlock()
		return
	}
	if h.hostRetryClosed {
		j.abandoned = true
		j.finishLocked(nil)
		h.hostRetryMu.Unlock()
		return
	}
	if j.pastDeadlineLocked() {
		j.expireLocked()
		h.hostRetryMu.Unlock()
		return
	}
	if !h.claimTrackedJob(j.jobID) {
		j.abandoned = true
		j.finishLocked(nil)
		h.hostRetryMu.Unlock()
		return
	}
	j.active = true
	j.queued = false
	j.attempts++
	generation := j.attempts
	if j.start.IsZero() {
		j.start = j.policy.now()
	}
	ctx := j.ctx
	cancel := func() {}
	// Only an established inventory wait budget owns lookup cancellation. The
	// first attempt retains the detached context used by ordinary CP scans.
	if !j.deadline.IsZero() {
		ctx, cancel = context.WithCancel(ctx)
	}
	j.cancel = cancel
	ctx = domain.WithScanPhaseUpdater(ctx, func(phase string) {
		h.hostRetryMu.Lock()
		defer h.hostRetryMu.Unlock()
		if !j.terminal && !j.expired && j.active && j.attempts == generation {
			h.ensureStatuses().markPhase(j.jobID, phase)
		}
	})
	ctx = domain.WithHostInventoryFailureReporter(ctx, func(report func(context.Context, error)) {
		h.hostRetryMu.Lock()
		defer h.hostRetryMu.Unlock()
		if !j.terminal && !j.expired && j.active && j.attempts == generation {
			j.reportFailure = report
		}
	})
	ctx = domain.WithHostInventoryReady(ctx, func() error {
		h.hostRetryMu.Lock()
		defer h.hostRetryMu.Unlock()
		if j.terminal || j.expired || !j.active || j.attempts != generation {
			return domain.ErrHostInventoryUnavailable
		}
		if j.pastDeadlineLocked() {
			j.expireLocked()
			return domain.ErrHostInventoryUnavailable
		}
		j.inventoryResolved = true
		j.stopTimersLocked()
		return nil
	})
	h.hostRetryMu.Unlock()
	err := h.scanService.ScanCP(ctx)
	cancel()
	h.hostRetryMu.Lock()
	defer h.hostRetryMu.Unlock()
	j.active = false
	j.cancel = nil
	if j.expired {
		j.finishLocked(domain.ErrHostInventoryUnavailable)
		return
	}
	if errors.Is(err, domain.ErrHostInventoryPending) && !j.inventoryResolved {
		if h.hostRetryClosed {
			j.abandoned = true
			j.finishLocked(nil)
			return
		}
		if j.deadline.IsZero() {
			j.deadline = j.policy.now().Add(j.policy.maxAge)
			j.deadlineTimer = j.policy.afterFunc(j.policy.maxAge, func() {
				h.hostRetryMu.Lock()
				defer h.hostRetryMu.Unlock()
				if !j.terminal && !j.inventoryResolved {
					j.expireLocked()
				}
			})
		}
		if j.attempts >= j.policy.maxAttempts || j.pastDeadlineLocked() {
			j.expireLocked()
			return
		}
		h.ensureStatuses().markInventoryWaiting(j.jobID)
		delay := 5 * time.Second
		for n := 1; n < j.attempts && delay < 60*time.Second; n++ {
			delay *= 2
		}
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
		delay = j.policy.jitter(delay)
		if remaining := j.deadline.Sub(j.policy.now()); delay > remaining {
			delay = remaining
		}
		attempt := j.attempts
		j.delayTimer = j.policy.afterFunc(delay, func() {
			h.hostRetryMu.Lock()
			if j.terminal || j.expired || j.inventoryResolved || j.queued || j.active || j.attempts != attempt {
				h.hostRetryMu.Unlock()
				return
			}
			if h.hostRetryClosed {
				j.abandoned = true
				j.finishLocked(nil)
				h.hostRetryMu.Unlock()
				return
			}
			if j.pastDeadlineLocked() {
				j.expireLocked()
				h.hostRetryMu.Unlock()
				return
			}
			j.queued = true
			h.hostRetryMu.Unlock()
			j.submit()
		})
		logger.L().Ctx(j.ctx).Info("waiting for host SBOM", helpers.Int("attempt", j.attempts), helpers.String("retryAfter", delay.String()), helpers.Error(err))
		return
	}
	j.finishLocked(err)
}

func (j *hostInventoryJob) stopTimersLocked() {
	if j.delayTimer != nil {
		j.delayTimer.Stop()
		j.delayTimer = nil
	}
	if j.deadlineTimer != nil {
		j.deadlineTimer.Stop()
		j.deadlineTimer = nil
	}
}

func (j *hostInventoryJob) expireLocked() {
	if j.terminal || j.inventoryResolved {
		return
	}
	j.expired = true
	j.stopTimersLocked()
	if j.cancel != nil {
		j.cancel()
	}
	// A canceled lookup still owns its worker and admission until it actually exits.
	if !j.active {
		j.finishLocked(domain.ErrHostInventoryUnavailable)
	}
}

func (j *hostInventoryJob) finishLocked(err error) {
	if j.terminal || j.active {
		return
	}
	j.terminal = true
	j.stopTimersLocked()
	delete(j.h.hostRetries, j)
	// Claim the report before unlocking. Keep the public job and admission active
	// until I/O finishes, but protect it from Shutdown's queued-abandonment sweep.
	// Other jobs and timer callbacks must remain free to use the lifecycle lock.
	if j.expired && !j.abandoned && j.reportFailure != nil {
		j.h.claimTrackedJob(j.jobID)
		report := j.reportFailure
		j.reportFailure = nil
		j.h.hostRetryMu.Unlock()
		report(j.ctx, err)
		j.h.hostRetryMu.Lock()
	}
	defer j.h.release()
	if j.abandoned {
		j.h.ensureStatuses().markAbandoned(j.jobID, domain.ScanReasonShutdownAbandoned)
		return
	}
	outcome := "success"
	if errors.Is(err, domain.ErrPartialContainerProfile) {
		outcome = "partial"
	} else if err != nil {
		outcome = "error"
	}
	j.h.recordScan(j.ctx, "scanCP", j.start, outcome, err)
	if outcome == "error" {
		reason := scanFailureReason(outcome, err)
		if errors.Is(err, domain.ErrHostInventoryUnavailable) {
			reason = "host_inventory_unavailable"
		}
		j.h.ensureStatuses().markFailed(j.jobID, reason)
		logger.L().Ctx(j.ctx).Error("service error - ScanCP", append([]helpers.IDetails{helpers.Error(err)}, j.details...)...)
	} else {
		j.h.ensureStatuses().markSucceeded(j.jobID)
		if err != nil {
			logger.L().Ctx(j.ctx).Warning("service warning - ScanCP", append([]helpers.IDetails{helpers.Error(err)}, j.details...)...)
		}
	}
}

func (h *HTTPController) stopHostInventoryRetries() {
	h.hostRetryMu.Lock()
	defer h.hostRetryMu.Unlock()
	h.hostRetryClosed = true
	for j := range h.hostRetries {
		j.stopTimersLocked()
		if !j.active {
			j.abandoned = true
			j.finishLocked(nil)
		}
	}
}
