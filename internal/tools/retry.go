package tools

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/metrics"
)

type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Backoff     float64
	// MaxRetryAfter bounds a delay taken from a registry's Retry-After. That number is
	// chosen by the registry rather than by us, and nothing else on this path stops the
	// clock: the scan context is built with context.WithoutCancel, so it carries no
	// deadline, and the sidecar's own scanTimeout only wraps SBOM generation, which comes
	// after this. A ceiling well under the scan timeout keeps the header useful without
	// letting one response decide how long a worker is held. Non-positive falls back to
	// MaxWait.
	MaxRetryAfter time.Duration
}

func Default429RetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   3,
		InitialWait:   500 * time.Millisecond,
		MaxWait:       2 * time.Second,
		Backoff:       2.0,
		MaxRetryAfter: 30 * time.Second,
	}
}

// retryAfterCeiling is the largest delay a Retry-After is allowed to ask for.
func (c RetryConfig) retryAfterCeiling() time.Duration {
	if c.MaxRetryAfter > 0 {
		return c.MaxRetryAfter
	}
	return c.MaxWait
}

func IsRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, domain.ErrTooManyRequests) {
		return true
	}
	var transportErr *transport.Error
	if errors.As(err, &transportErr) && transportErr.StatusCode == http.StatusTooManyRequests {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "TOOMANYREQUESTS") ||
		strings.Contains(errStr, "429 Too Many Requests") ||
		strings.Contains(errStr, "status code: 429") ||
		strings.Contains(errStr, "received status code: 429")
}

func ParseRetryAfter(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	errStr := err.Error()
	idx := strings.Index(errStr, "Retry-After:")
	if idx == -1 {
		return 0, false
	}
	rawVal := strings.TrimSpace(errStr[idx+len("Retry-After:"):])
	spaceIdx := strings.IndexAny(rawVal, " \t\r\n,")
	numStr := rawVal
	if spaceIdx != -1 {
		numStr = rawVal[:spaceIdx]
	}
	if secs, parseErr := strconv.Atoi(numStr); parseErr == nil && secs > 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, parseErr := time.Parse(time.RFC1123, rawVal); parseErr == nil {
		d := time.Until(t)
		if d <= 0 {
			d = time.Second
		}
		return d, true
	}
	return 0, false
}

// RetryWithBackoff executes operation fn up to config.MaxAttempts times if fn returns an error for which isRetryable(err) is true.
func RetryWithBackoff[T any](ctx context.Context, operation string, config RetryConfig, isRetryable func(error) bool, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T
	wait := config.InitialWait

	for attempt := 1; ; attempt++ {
		val, err := fn(ctx)
		if err == nil {
			if attempt > 1 {
				metrics.RecordRetryAttempt(ctx, operation, metrics.RetryOutcomeSuccess)
			}
			return val, nil
		}

		if attempt >= config.MaxAttempts || !isRetryable(err) {
			if isRetryable(err) {
				metrics.RecordRetryAttempt(ctx, operation, metrics.RetryOutcomeExhausted)
			}
			return zero, err
		}

		if ctx.Err() != nil {
			return zero, ctx.Err()
		}

		metrics.RecordRetryAttempt(ctx, operation, metrics.RetryOutcomeAttempt)

		delay := wait
		if retryAfter, ok := ParseRetryAfter(err); ok {
			delay = retryAfter
			if ceiling := config.retryAfterCeiling(); delay > ceiling {
				logger.L().Ctx(ctx).Debug("capping Retry-After to the configured ceiling",
					helpers.String("requested", retryAfter.String()),
					helpers.String("ceiling", ceiling.String()))
				delay = ceiling
			}
		} else {
			if delay > 0 {
				jitter := time.Duration(rand.Float64() * 0.25 * float64(delay))
				delay += jitter
			}
			if delay > config.MaxWait {
				delay = config.MaxWait
			}
		}

		logger.L().Ctx(ctx).Debug("retrying operation after 429 rate limit",
			helpers.Int("attempt", attempt),
			helpers.Int("maxAttempts", config.MaxAttempts),
			helpers.String("delay", delay.String()),
			helpers.Error(err))

		wait = time.Duration(float64(wait) * config.Backoff)
		if wait > config.MaxWait {
			wait = config.MaxWait
		}

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return zero, ctx.Err()
		}
	}
}
