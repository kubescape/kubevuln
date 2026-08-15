package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsRateLimitError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "domain.ErrTooManyRequests",
			err:      domain.ErrTooManyRequests,
			expected: true,
		},
		{
			name:     "wrapped domain.ErrTooManyRequests",
			err:      fmt.Errorf("sidecar error: %w", domain.ErrTooManyRequests),
			expected: true,
		},
		{
			name:     "transport.Error with 429",
			err:      &transport.Error{StatusCode: http.StatusTooManyRequests},
			expected: true,
		},
		{
			name:     "string 429 error",
			err:      errors.New("received status code: 429"),
			expected: true,
		},
		{
			name:     "non-429 error",
			err:      errors.New("401 Unauthorized"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsRateLimitError(tt.err))
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	errWithHeader := errors.New("received status code 429 Retry-After: 5 seconds")

	dur, ok := ParseRetryAfter(errWithHeader)
	assert.True(t, ok)
	assert.Equal(t, 5*time.Second, dur)

	futureTime := time.Now().Add(10 * time.Second).Format(time.RFC1123)
	errWithDateHeader := fmt.Errorf("received status code 429 Retry-After: %s", futureTime)
	durDate, okDate := ParseRetryAfter(errWithDateHeader)
	assert.True(t, okDate)
	assert.Greater(t, durDate, 0*time.Second)

	noHdrErr := errors.New("received status code 429")
	_, ok = ParseRetryAfter(noHdrErr)
	assert.False(t, ok)

	nilErr, ok := ParseRetryAfter(nil)
	assert.False(t, ok)
	assert.Equal(t, time.Duration(0), nilErr)
}

func TestRetryWithBackoff_SuccessFirstAttempt(t *testing.T) {
	calls := 0
	config := RetryConfig{
		MaxAttempts: 3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     50 * time.Millisecond,
		Backoff:     2.0,
	}

	res, err := RetryWithBackoff(context.Background(), "test_op", config, IsRateLimitError, func(ctx context.Context) (string, error) {
		calls++
		return "ok", nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "ok", res)
	assert.Equal(t, 1, calls)
}

func TestRetryWithBackoff_SuccessAfterRetry(t *testing.T) {
	calls := 0
	config := RetryConfig{
		MaxAttempts: 3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     50 * time.Millisecond,
		Backoff:     2.0,
	}

	res, err := RetryWithBackoff(context.Background(), "test_op", config, IsRateLimitError, func(ctx context.Context) (string, error) {
		calls++
		if calls < 2 {
			return "", &transport.Error{StatusCode: http.StatusTooManyRequests}
		}
		return "recovered", nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "recovered", res)
	assert.Equal(t, 2, calls)
}

func TestRetryWithBackoff_ExhaustedRetries(t *testing.T) {
	calls := 0
	config := RetryConfig{
		MaxAttempts: 3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     50 * time.Millisecond,
		Backoff:     2.0,
	}

	rateErr := &transport.Error{StatusCode: http.StatusTooManyRequests}
	_, err := RetryWithBackoff(context.Background(), "test_op", config, IsRateLimitError, func(ctx context.Context) (string, error) {
		calls++
		return "", rateErr
	})

	assert.Equal(t, rateErr, err)
	assert.Equal(t, 3, calls)
}

func TestRetryWithBackoff_MetricsRecording(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)
	defer func() { _ = m.Shutdown(context.Background()) }()

	config := RetryConfig{
		MaxAttempts: 2,
		InitialWait: 5 * time.Millisecond,
		MaxWait:     20 * time.Millisecond,
		Backoff:     2.0,
	}

	calls := 0
	_, err = RetryWithBackoff(context.Background(), "test_op", config, IsRateLimitError, func(ctx context.Context) (string, error) {
		calls++
		if calls == 1 {
			return "", &transport.Error{StatusCode: http.StatusTooManyRequests}
		}
		return "ok", nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 2, calls)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, `kubevuln_retry_attempts_total{operation="test_op",outcome="attempt"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_retry_attempts_total{operation="test_op",outcome="success"} 1`), body)
}

func TestRetryWithBackoff_MetricsRecordingExhausted(t *testing.T) {
	m, err := metrics.New()
	require.NoError(t, err)
	defer func() { _ = m.Shutdown(context.Background()) }()

	config := RetryConfig{
		MaxAttempts: 2,
		InitialWait: 5 * time.Millisecond,
		MaxWait:     20 * time.Millisecond,
		Backoff:     2.0,
	}

	rateErr := &transport.Error{StatusCode: http.StatusTooManyRequests}
	_, err = RetryWithBackoff(context.Background(), "test_exhausted_op", config, IsRateLimitError, func(ctx context.Context) (string, error) {
		return "", rateErr
	})

	assert.Equal(t, rateErr, err)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, `kubevuln_retry_attempts_total{operation="test_exhausted_op",outcome="attempt"} 1`), body)
	assert.True(t, strings.Contains(body, `kubevuln_retry_attempts_total{operation="test_exhausted_op",outcome="exhausted"} 1`), body)
}

// A Retry-After is chosen by the registry, and nothing else on this path bounds the wait:
// the scan context is built with context.WithoutCancel so it has no deadline, and the
// sidecar's scanTimeout only wraps SBOM generation, which happens after source resolution.
// Left uncapped, one 429 response decides how long a worker is held.
func TestRetryWithBackoff_CapsRetryAfter(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:   3,
		InitialWait:   time.Millisecond,
		MaxWait:       2 * time.Millisecond,
		Backoff:       2.0,
		MaxRetryAfter: 20 * time.Millisecond,
	}
	// Two orders of magnitude above the ceiling, standing in for a registry asking for hours.
	rateLimited := errors.New("429 Too Many Requests, Retry-After: 2")

	attempts := 0
	start := time.Now()
	_, err := RetryWithBackoff(context.Background(), "source_resolution", cfg, IsRateLimitError,
		func(context.Context) (int, error) {
			attempts++
			return 0, rateLimited
		})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Equal(t, cfg.MaxAttempts, attempts)
	// Two waits at the 20ms ceiling, not two at the 2s the header asked for.
	assert.Less(t, elapsed, 500*time.Millisecond,
		"Retry-After must be capped at MaxRetryAfter, took %s", elapsed)
}

// The cap must not turn the header off: a Retry-After under the ceiling is still waited out,
// which is the whole point of reading it.
func TestRetryWithBackoff_HonoursRetryAfterUnderTheCeiling(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:   2,
		InitialWait:   time.Microsecond,
		MaxWait:       time.Microsecond,
		Backoff:       2.0,
		MaxRetryAfter: time.Minute,
	}
	// Well above the backoff this config would otherwise produce, so the wait can only have
	// come from the header.
	rateLimited := errors.New("429 Too Many Requests, Retry-After: 1")

	start := time.Now()
	_, err := RetryWithBackoff(context.Background(), "source_resolution", cfg, IsRateLimitError,
		func(context.Context) (int, error) { return 0, rateLimited })
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.GreaterOrEqual(t, elapsed, time.Second, "a Retry-After below the ceiling must still be honoured")
}

// A config that never sets MaxRetryAfter still gets a bound rather than an open-ended wait.
func TestRetryWithBackoff_UnsetCeilingFallsBackToMaxWait(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts: 2,
		InitialWait: time.Millisecond,
		MaxWait:     10 * time.Millisecond,
		Backoff:     2.0,
	}
	rateLimited := errors.New("429 Too Many Requests, Retry-After: 2")

	start := time.Now()
	_, err := RetryWithBackoff(context.Background(), "source_resolution", cfg, IsRateLimitError,
		func(context.Context) (int, error) { return 0, rateLimited })
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Less(t, elapsed, 500*time.Millisecond, "took %s", elapsed)
}

func TestRetryWithBackoff_NonRetryableErrorNoRetry(t *testing.T) {
	calls := 0
	config := RetryConfig{
		MaxAttempts: 3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     50 * time.Millisecond,
		Backoff:     2.0,
	}

	nonRetryErr := errors.New("401 Unauthorized")
	_, err := RetryWithBackoff(context.Background(), "test_non_retry", config, IsRateLimitError, func(ctx context.Context) (string, error) {
		calls++
		return "", nonRetryErr
	})

	assert.Equal(t, nonRetryErr, err)
	assert.Equal(t, 1, calls)
}

func TestRetryWithBackoff_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	config := RetryConfig{
		MaxAttempts: 5,
		InitialWait: 50 * time.Millisecond,
		MaxWait:     200 * time.Millisecond,
		Backoff:     2.0,
	}

	_, err := RetryWithBackoff(ctx, "test_canceled", config, IsRateLimitError, func(c context.Context) (string, error) {
		calls++
		if calls == 1 {
			cancel() // cancel context on first failure
		}
		return "", &transport.Error{StatusCode: http.StatusTooManyRequests}
	})

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, calls)
}

func TestRetryWithBackoff_ContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled

	calls := 0
	config := FastRetryConfig()
	_, err := RetryWithBackoff(ctx, "test_pre_canceled", config, IsRateLimitError, func(c context.Context) (string, error) {
		calls++
		return "ok", nil
	})

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, calls, "fn must not be called when context is already canceled")
}
