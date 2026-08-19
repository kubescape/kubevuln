package domain

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScanStatusJSON_OmitsZeroLifecycleTimestamps(t *testing.T) {
	status := ScanStatus{
		JobID:      "job-queued",
		Endpoint:   "generateSBOM",
		State:      ScanStateQueued,
		Phase:      string(ScanStateQueued),
		AcceptedAt: time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
		UpdatedAt:  time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
	}

	body, err := json.Marshal(status)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	require.NotContains(t, got, "startedAt")
	require.NotContains(t, got, "finishedAt")
}

// UpdateScanPhase is what every phase reported by /v1/scanStatus travels through, from
// twenty call sites across the four scan flows, and neither it nor WithScanPhaseUpdater had
// any coverage. The round trip below is the part that matters: nothing asserted that a phase
// handed to UpdateScanPhase reaches the function WithScanPhaseUpdater stored, so changing the
// context key or the stored signature would have silently stopped all twenty reporting
// without failing anything.
func TestUpdateScanPhase_ReachesTheUpdater(t *testing.T) {
	var got []string
	ctx := WithScanPhaseUpdater(context.Background(), func(phase string) {
		got = append(got, phase)
	})

	UpdateScanPhase(ctx, "sbom_generation")
	UpdateScanPhase(ctx, "cve_matching")
	UpdateScanPhase(ctx, "result_upload")

	require.Equal(t, []string{"sbom_generation", "cve_matching", "result_upload"}, got,
		"each phase should reach the updater, in the order reported")
}

// The rest of UpdateScanPhase is refusals, and each one stands between a scan and a panic or
// a blanked phase. A scan flow calls it unconditionally; whether anything is listening is the
// caller's business, not the scan's.
func TestUpdateScanPhase_RefusesWhatItShould(t *testing.T) {
	t.Run("an empty phase is ignored rather than blanking the current one", func(t *testing.T) {
		called := false
		ctx := WithScanPhaseUpdater(context.Background(), func(string) { called = true })

		UpdateScanPhase(ctx, "")

		assert.False(t, called, "an empty phase must not reach the updater")
	})

	t.Run("no updater in context is a no-op", func(t *testing.T) {
		assert.NotPanics(t, func() {
			UpdateScanPhase(context.Background(), "cve_matching")
		}, "a scan running without status tracking still calls this")
	})

	t.Run("a nil updater stored in context is a no-op", func(t *testing.T) {
		// WithScanPhaseUpdater will store a nil func, and the type assertion succeeds on it,
		// so the nil check in UpdateScanPhase is the only thing between this and a panic.
		ctx := WithScanPhaseUpdater(context.Background(), nil)

		assert.NotPanics(t, func() {
			UpdateScanPhase(ctx, "cve_matching")
		})
	})

	t.Run("a value of another type under the key is a no-op", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), scanPhaseUpdaterKey{}, "not a function")

		assert.NotPanics(t, func() {
			UpdateScanPhase(ctx, "cve_matching")
		})
	})
}

// The key is an unexported struct type, so nothing outside this package can collide with it
// and no other package's context value can be mistaken for an updater.
func TestScanPhaseUpdater_KeyIsPrivateToThisPackage(t *testing.T) {
	ctx := WithScanPhaseUpdater(context.Background(), func(string) {})

	assert.Nil(t, ctx.Value("scanPhaseUpdaterKey"), "a string key must not resolve the updater")
	assert.Nil(t, ctx.Value(struct{}{}), "an unrelated empty struct must not resolve it either")
	assert.NotNil(t, ctx.Value(scanPhaseUpdaterKey{}), "the package's own key does")
}

// ScanCP fans a single request out over several images and reports phases from the loop, so
// the updater is reached repeatedly from the same context. It is also called from the worker
// goroutine while the request goroutine has already returned.
func TestUpdateScanPhase_ConcurrentReportersShareOneContext(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	ctx := WithScanPhaseUpdater(context.Background(), func(phase string) {
		mu.Lock()
		defer mu.Unlock()
		seen[phase]++
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			UpdateScanPhase(ctx, "sbom_generation")
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 50, seen["sbom_generation"])
}

// A derived context overrides the updater it was derived from, which is what lets a
// sub-scan report to its own job without disturbing the parent's.
func TestWithScanPhaseUpdater_InnerOverridesOuter(t *testing.T) {
	var outer, inner []string
	outerCtx := WithScanPhaseUpdater(context.Background(), func(p string) { outer = append(outer, p) })
	innerCtx := WithScanPhaseUpdater(outerCtx, func(p string) { inner = append(inner, p) })

	UpdateScanPhase(innerCtx, "cve_matching")
	UpdateScanPhase(outerCtx, "result_upload")

	assert.Equal(t, []string{"cve_matching"}, inner)
	assert.Equal(t, []string{"result_upload"}, outer, "the outer updater is unaffected")
}
