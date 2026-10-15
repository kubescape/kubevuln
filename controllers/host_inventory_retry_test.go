package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/stretchr/testify/require"
	"schneider.vip/problem"
)

type inventoryClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*inventoryFakeTimer
}
type inventoryFakeTimer struct {
	clock   *inventoryClock
	at      time.Time
	f       func()
	stopped bool
}

func (t *inventoryFakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}
func (c *inventoryClock) time() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *inventoryClock) after(d time.Duration, f func()) inventoryTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &inventoryFakeTimer{clock: c, at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return t
}
func (c *inventoryClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var next *inventoryFakeTimer
		for _, t := range c.timers {
			if !t.stopped && !t.at.After(c.now) && (next == nil || t.at.Before(next.at)) {
				next = t
			}
		}
		if next != nil {
			next.stopped = true
		}
		c.mu.Unlock()
		if next == nil {
			return
		}
		next.f()
	}
}

type inventoryRetryService struct {
	*services.MockScanService
	scan func(context.Context) error
}

func (s inventoryRetryService) ScanCP(ctx context.Context) error { return s.scan(ctx) }
func retryController(t *testing.T, scan func(context.Context) error) (*HTTPController, *inventoryClock) {
	t.Helper()
	clock := &inventoryClock{now: time.Now()}
	h := NewHTTPController(inventoryRetryService{services.NewMockScanService(true), scan}, 1).WithMaxQueueDepth(2)
	h.hostRetryPolicy = &hostInventoryRetryPolicy{now: clock.time, afterFunc: clock.after, jitter: func(d time.Duration) time.Duration { return d }, maxAttempts: 20, maxAge: 15 * time.Minute}
	t.Cleanup(func() { h.Shutdown(time.Second) })
	return h, clock
}
func admitRetry(t *testing.T, h *HTTPController, id string) {
	t.Helper()
	require.True(t, h.tryAdmit())
	require.True(t, h.ensureStatuses().recordAccepted(id, "scanCP"))
	h.runCPScan(context.Background(), id)
}
func awaitRetry(t *testing.T, h *HTTPController, id string, state domain.ScanState) domain.ScanStatus {
	t.Helper()
	require.Eventually(t, func() bool {
		h.hostRetryMu.Lock()
		defer h.hostRetryMu.Unlock()
		s, _ := h.ensureStatuses().get(id)
		return s.State == state
	}, time.Second, time.Millisecond)
	s, _ := h.ensureStatuses().get(id)
	return s
}
func awaitWaiting(t *testing.T, h *HTTPController, id string) domain.ScanStatus {
	t.Helper()
	require.Eventually(t, func() bool {
		h.hostRetryMu.Lock()
		defer h.hostRetryMu.Unlock()
		for j := range h.hostRetries {
			if j.jobID == id && !j.active && j.delayTimer != nil {
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	s, _ := h.ensureStatuses().get(id)
	return s
}

func TestInventoryRetryReadyPreservesJobAndFreesWorker(t *testing.T) {
	var calls atomic.Int32
	h, c := retryController(t, func(ctx context.Context) error {
		if calls.Add(1) < 3 {
			return domain.ErrHostInventoryPending
		}
		return domain.AcceptHostInventory(ctx)
	})
	admitRetry(t, h, "host")
	waiting := awaitWaiting(t, h, "host")
	require.Nil(t, waiting.FinishedAt)
	require.NotNil(t, waiting.StartedAt)
	require.EqualValues(t, 1, h.pending.Load())
	ran := make(chan struct{})
	require.True(t, h.submit(func() { close(ran) }))
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("waiting consumed worker")
	}
	c.advance(5 * time.Second)
	require.Eventually(t, func() bool { return calls.Load() == 2 }, time.Second, time.Millisecond)
	awaitWaiting(t, h, "host")
	c.advance(10 * time.Second)
	done := awaitRetry(t, h, "host", domain.ScanStateSucceeded)
	require.Equal(t, waiting.AcceptedAt, done.AcceptedAt)
	require.Equal(t, waiting.StartedAt, done.StartedAt)
	require.EqualValues(t, 0, h.pending.Load())
	require.EqualValues(t, 3, calls.Load())
}
func TestInventoryRetryAdmissionAndDuplicate(t *testing.T) {
	h, _ := retryController(t, func(context.Context) error { return domain.ErrHostInventoryPending })
	h.maxQueueDepth = 1
	admitRetry(t, h, "host")
	awaitWaiting(t, h, "host")
	for _, tc := range []struct {
		id   string
		code int
	}{{"host", http.StatusConflict}, {"other", http.StatusServiceUnavailable}} {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		require.False(t, h.admitJob(ctx, context.Background(), "scanCP", tc.id, problem.Detail("test")))
		require.Equal(t, tc.code, w.Code)
	}
	require.EqualValues(t, 1, h.pending.Load())
}
func TestInventoryRetryAttemptLimitAndTerminalError(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		attempts int
	}{{"pending", domain.ErrHostInventoryPending, 3}, {"terminal", errors.New("forbidden inventory"), 1}, {"partial", domain.ErrPartialContainerProfile, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			h, c := retryController(t, func(context.Context) error { calls.Add(1); return tc.err })
			h.hostRetryPolicy.maxAttempts = 3
			admitRetry(t, h, "host")
			for n := 1; n < tc.attempts; n++ {
				awaitWaiting(t, h, "host")
				c.advance(time.Duration(5<<(n-1)) * time.Second)
				require.Eventually(t, func() bool { return int(calls.Load()) > n }, time.Second, time.Millisecond)
			}
			state := domain.ScanStateFailed
			if tc.name == "partial" {
				state = domain.ScanStateSucceeded
			}
			s := awaitRetry(t, h, "host", state)
			if tc.name == "pending" {
				require.Equal(t, "host_inventory_unavailable", s.Reason)
			}
			require.EqualValues(t, tc.attempts, calls.Load())
			require.EqualValues(t, 0, h.pending.Load())
		})
	}
}
func TestInventoryRetryExpiryActiveLookupRetainsAdmission(t *testing.T) {
	var calls atomic.Int32
	lookup := make(chan context.Context, 1)
	exit := make(chan struct{})
	accept := make(chan error, 1)
	h, c := retryController(t, func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			return domain.ErrHostInventoryPending
		}
		lookup <- ctx
		<-exit
		err := domain.AcceptHostInventory(ctx)
		accept <- err
		domain.UpdateScanPhase(ctx, "late publication")
		return err
	})
	admitRetry(t, h, "host")
	awaitWaiting(t, h, "host")
	c.advance(5 * time.Second)
	ctx := <-lookup
	c.advance(15 * time.Minute)
	require.Error(t, ctx.Err())
	require.EqualValues(t, 1, h.pending.Load())
	require.True(t, h.ensureStatuses().isActive("host"))
	close(exit)
	require.Error(t, <-accept)
	awaitRetry(t, h, "host", domain.ScanStateFailed)
	require.EqualValues(t, 0, h.pending.Load())
}
func TestInventoryRetryReadyDisarmsDeadline(t *testing.T) {
	var calls atomic.Int32
	ready := make(chan struct{})
	exit := make(chan struct{})
	h, c := retryController(t, func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			return domain.ErrHostInventoryPending
		}
		err := domain.AcceptHostInventory(ctx)
		if err != nil {
			return err
		}
		close(ready)
		<-exit
		return ctx.Err()
	})
	admitRetry(t, h, "host")
	awaitWaiting(t, h, "host")
	c.advance(5 * time.Second)
	<-ready
	c.advance(time.Hour)
	require.EqualValues(t, 1, h.pending.Load())
	close(exit)
	awaitRetry(t, h, "host", domain.ScanStateSucceeded)
}
func TestInventoryRetryQueuedExpiryAndStaleCallbacks(t *testing.T) {
	var calls atomic.Int32
	var old context.Context
	h, c := retryController(t, func(ctx context.Context) error { old = ctx; calls.Add(1); return domain.ErrHostInventoryPending })
	admitRetry(t, h, "host")
	awaitWaiting(t, h, "host")
	c.mu.Lock()
	callbacks := append([]*inventoryFakeTimer(nil), c.timers...)
	c.mu.Unlock()
	block := make(chan struct{})
	started := make(chan struct{})
	h.submit(func() { close(started); <-block })
	<-started
	c.advance(5 * time.Second)
	c.advance(15 * time.Minute)
	awaitRetry(t, h, "host", domain.ScanStateFailed)
	require.EqualValues(t, 0, h.pending.Load())
	require.True(t, h.ensureStatuses().recordAccepted("host", "scanCP"))
	domain.UpdateScanPhase(old, "stale")
	require.Error(t, domain.AcceptHostInventory(old))
	for _, timer := range callbacks {
		timer.f()
	}
	s, _ := h.ensureStatuses().get("host")
	require.Equal(t, "queued", s.Phase)
	close(block)
	barrier := make(chan struct{})
	h.submit(func() { close(barrier) })
	<-barrier
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 0, h.pending.Load())
}
func TestInventoryRetryEmptyJobIDAndShutdown(t *testing.T) {
	var calls atomic.Int32
	h, c := retryController(t, func(context.Context) error { calls.Add(1); return domain.ErrHostInventoryPending })
	admitRetry(t, h, "")
	require.Eventually(t, func() bool {
		h.hostRetryMu.Lock()
		defer h.hostRetryMu.Unlock()
		for j := range h.hostRetries {
			if j.delayTimer != nil {
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	h.Shutdown(time.Second)
	require.EqualValues(t, 0, h.pending.Load())
	c.advance(time.Hour)
	require.EqualValues(t, 1, calls.Load())
}
func TestInventoryRetryShutdownRunningPending(t *testing.T) {
	started := make(chan struct{})
	exit := make(chan struct{})
	h, c := retryController(t, func(context.Context) error { close(started); <-exit; return domain.ErrHostInventoryPending })
	admitRetry(t, h, "host")
	<-started
	h.Shutdown(time.Millisecond)
	require.EqualValues(t, 1, h.pending.Load())
	close(exit)
	awaitRetry(t, h, "host", domain.ScanStateAbandoned)
	require.EqualValues(t, 0, h.pending.Load())
	c.advance(time.Hour)
}
func TestInventoryRetryJitterBounds(t *testing.T) {
	policy := defaultHostInventoryRetryPolicy()
	for n := 0; n < 1000; n++ {
		d := policy.jitter(time.Minute)
		require.GreaterOrEqual(t, d, 48*time.Second)
		require.LessOrEqual(t, d, 72*time.Second)
	}
}

func TestInventoryRetryReadyChecksClockBeforeDelayedDeadlineCallback(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	exit := make(chan struct{})
	accepted := make(chan error, 1)
	h, c := retryController(t, func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			return domain.ErrHostInventoryPending
		}
		close(started)
		<-exit
		err := domain.AcceptHostInventory(ctx)
		accepted <- err
		return err
	})
	admitRetry(t, h, "host")
	awaitWaiting(t, h, "host")
	c.advance(5 * time.Second)
	<-started
	// Move wall time without dispatching callbacks: acceptance itself must check it.
	c.mu.Lock()
	c.now = c.now.Add(time.Hour)
	c.mu.Unlock()
	close(exit)
	require.ErrorIs(t, <-accepted, domain.ErrHostInventoryUnavailable)
	awaitRetry(t, h, "host", domain.ScanStateFailed)
	require.EqualValues(t, 0, h.pending.Load())
}

func TestInventoryRetryShutdownDuringSubmitCallback(t *testing.T) {
	h, c := retryController(t, func(context.Context) error { return domain.ErrHostInventoryPending })
	admitRetry(t, h, "host")
	awaitWaiting(t, h, "host")
	entered := make(chan struct{})
	release := make(chan struct{})
	h.submitGate.Lock()
	h.submitBeforeHook = func() { close(entered); <-release }
	h.submitGate.Unlock()
	timerDone := make(chan struct{})
	go func() { c.advance(5 * time.Second); close(timerDone) }()
	<-entered
	stopped := make(chan struct{})
	go func() { h.Shutdown(time.Second); close(stopped) }()
	close(release)
	<-timerDone
	<-stopped
	awaitRetry(t, h, "host", domain.ScanStateAbandoned)
	require.EqualValues(t, 0, h.pending.Load())
	c.advance(time.Hour)
}

func TestInventoryRetryMetricsOnlyRecordTerminalOnce(t *testing.T) {
	h, c := retryController(t, func(context.Context) error { return domain.ErrHostInventoryPending })
	m, err := metrics.New()
	require.NoError(t, err)
	_, err = h.WithMetrics(m)
	require.NoError(t, err)
	scrape := func() string {
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		return w.Body.String()
	}
	admitRetry(t, h, "host")
	awaitWaiting(t, h, "host")
	require.NotContains(t, scrape(), `kubevuln_scans_completed_total{endpoint="scanCP"`)
	c.mu.Lock()
	timers := append([]*inventoryFakeTimer(nil), c.timers...)
	c.mu.Unlock()
	c.advance(time.Hour)
	awaitRetry(t, h, "host", domain.ScanStateFailed)
	for _, timer := range timers {
		timer.f()
	}
	require.Contains(t, scrape(), `kubevuln_scans_completed_total{endpoint="scanCP",outcome="error",reason="unexpected_error"} 1`)
	require.EqualValues(t, 0, h.pending.Load())
}

func TestInventoryRetryTerminalReportOnceOutsideLock(t *testing.T) {
	for _, mode := range []string{"attempts", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var reports atomic.Int32
			entered := make(chan context.Context, 1)
			release := make(chan struct{})
			var oldCtx context.Context
			h, c := retryController(t, func(ctx context.Context) error {
				oldCtx = ctx
				domain.RegisterHostInventoryFailureReporter(ctx, func(reportCtx context.Context, err error) {
					reports.Add(1)
					if !errors.Is(err, domain.ErrHostInventoryUnavailable) {
						t.Errorf("wrong report error: %v", err)
					}
					entered <- reportCtx
					<-release
				})
				return domain.ErrHostInventoryPending
			})
			if mode == "attempts" {
				h.hostRetryPolicy.maxAttempts = 1
			}
			admitRetry(t, h, "host")
			var timerDone chan struct{}
			if mode == "deadline" {
				awaitWaiting(t, h, "host")
				require.EqualValues(t, 0, reports.Load())
				timerDone = make(chan struct{})
				go func() { c.advance(time.Hour); close(timerDone) }()
			}
			reportCtx := <-entered
			require.NoError(t, reportCtx.Err())
			// This lock/read would deadlock if reporting retained the lifecycle lock.
			h.hostRetryMu.Lock()
			require.EqualValues(t, 1, h.pending.Load())
			h.hostRetryMu.Unlock()
			require.True(t, h.ensureStatuses().isActive("host"))
			domain.RegisterHostInventoryFailureReporter(oldCtx, func(context.Context, error) { t.Error("stale reporter registered") })
			domain.UpdateScanPhase(oldCtx, "stale publication")
			h.Shutdown(time.Millisecond)
			require.True(t, h.ensureStatuses().isActive("host"))
			require.EqualValues(t, 1, h.pending.Load())
			close(release)
			if timerDone != nil {
				<-timerDone
			}
			awaitRetry(t, h, "host", domain.ScanStateFailed)
			require.EqualValues(t, 1, reports.Load())
			require.EqualValues(t, 0, h.pending.Load())
			c.advance(time.Hour)
			require.EqualValues(t, 1, reports.Load())
		})
	}
}

func TestInventoryRetryNoBudgetReportForImmediateErrorOrShutdown(t *testing.T) {
	for _, mode := range []string{"terminal", "shutdown", "ready"} {
		t.Run(mode, func(t *testing.T) {
			var reports atomic.Int32
			h, c := retryController(t, func(ctx context.Context) error {
				domain.RegisterHostInventoryFailureReporter(ctx, func(context.Context, error) { reports.Add(1) })
				switch mode {
				case "terminal":
					return domain.ErrHostInventoryUnavailable
				case "ready":
					return domain.AcceptHostInventory(ctx)
				default:
					return domain.ErrHostInventoryPending
				}
			})
			admitRetry(t, h, "host")
			switch mode {
			case "shutdown":
				awaitWaiting(t, h, "host")
				h.Shutdown(time.Second)
				awaitRetry(t, h, "host", domain.ScanStateAbandoned)
			case "terminal":
				awaitRetry(t, h, "host", domain.ScanStateFailed)
			case "ready":
				awaitRetry(t, h, "host", domain.ScanStateSucceeded)
			}
			c.advance(time.Hour)
			require.EqualValues(t, 0, reports.Load())
		})
	}
}

func TestInventoryRetryFailureResolutionDisarmsBudget(t *testing.T) {
	var calls, reports atomic.Int32
	resolved := make(chan struct{})
	exit := make(chan struct{})
	h, c := retryController(t, func(ctx context.Context) error {
		domain.RegisterHostInventoryFailureReporter(ctx, func(context.Context, error) { reports.Add(1) })
		if calls.Add(1) == 1 {
			return domain.ErrHostInventoryPending
		}
		if err := domain.AcceptHostInventoryFailure(ctx); err != nil {
			return err
		}
		close(resolved)
		<-exit
		return errors.New("terminal inventory validation failed")
	})
	admitRetry(t, h, "host")
	awaitWaiting(t, h, "host")
	c.advance(5 * time.Second)
	<-resolved
	c.advance(time.Hour)
	require.EqualValues(t, 0, reports.Load())
	require.EqualValues(t, 1, h.pending.Load())
	close(exit)
	awaitRetry(t, h, "host", domain.ScanStateFailed)
	require.EqualValues(t, 0, reports.Load())
}
