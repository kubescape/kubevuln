package tools

import (
	"context"
	"errors"
	"math"
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

// maxRetryAfterSeconds is the largest number of seconds that can be multiplied by
// time.Second without overflowing time.Duration's underlying int64 nanosecond count. A
// numeric Retry-After value beyond this wraps around to a negative time.Duration -- which
// RetryWithBackoff's ceiling check never catches (a negative delay is never ">" a positive
// ceiling) and time.After fires immediately for, turning backoff into a hot retry loop
// against whatever is rate-limiting it. Mirrors adapters/v1/backend.go's identical guard on
// the report-posting retry path's own Retry-After parsing (see #754, #877).
const maxRetryAfterSeconds = math.MaxInt64 / int64(time.Second)

// RetryConfig specifies configuration for retrying operations.
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

// Default429RetryConfig returns standard retry settings for 429 rate limits:
// 3 max attempts (1 initial attempt + 2 retries), starting at 500ms initial wait up to 2s,
// with a 30s ceiling on Retry-After.
func Default429RetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   3,
		InitialWait:   500 * time.Millisecond,
		MaxWait:       2 * time.Second,
		Backoff:       2.0,
		MaxRetryAfter: 30 * time.Second,
	}
}

// FastRetryConfig returns fast retry settings for unit testing (1ms initial wait up to 10ms).
func FastRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		InitialWait: 1 * time.Millisecond,
		MaxWait:     10 * time.Millisecond,
		Backoff:     2.0,
	}
}

// retryAfterCeiling is the largest delay a Retry-After is allowed to ask for.
func (c RetryConfig) retryAfterCeiling() time.Duration {
	if c.MaxRetryAfter > 0 {
		return c.MaxRetryAfter
	}
	return c.MaxWait
}

// IsRateLimitError reports whether err indicates a 429 Too Many Requests rate-limiting error.
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

// ParseRetryAfter attempts to extract a Retry-After duration from error text or header strings.
// Supports both numeric seconds ("120") and HTTP-date formats (RFC1123/RFC1123Z).
func ParseRetryAfter(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}
	errStr := err.Error()
	idx := strings.Index(strings.ToLower(errStr), "retry-after:")
	if idx != -1 {
		sub := strings.TrimSpace(errStr[idx+len("retry-after:"):])
		fields := strings.Fields(sub)
		if len(fields) > 0 {
			token := strings.Trim(fields[0], ";,")
			if seconds, parseErr := strconv.ParseInt(token, 10, 64); parseErr == nil && seconds > 0 && seconds <= maxRetryAfterSeconds {
				return time.Duration(seconds) * time.Second, true
			}
		}
		dateStr := sub
		if endIdx := strings.IndexAny(sub, "\r\n"); endIdx != -1 {
			dateStr = strings.TrimSpace(sub[:endIdx])
		}
		if t, parseErr := time.Parse(time.RFC1123, dateStr); parseErr == nil {
			if d := time.Until(t); d > 0 {
				return d, true
			}
		}
		if t, parseErr := time.Parse(time.RFC1123Z, dateStr); parseErr == nil {
			if d := time.Until(t); d > 0 {
				return d, true
			}
		}
	}
	return 0, false
}

// RetryWithBackoff executes operation fn up to config.MaxAttempts times if fn returns an error for which isRetryable(err) is true.
func RetryWithBackoff[T any](ctx context.Context, operation string, config RetryConfig, isRetryable func(error) bool, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T
	wait := config.InitialWait

	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}

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

		// Calculate wait duration with Retry-After header or backoff + jitter
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
				jitter := time.Duration(rand.Float64() * 0.25 * float64(delay)) // #nosec G404 -- jitter for retry backoff; not security-sensitive
				delay += jitter
			}
			if delay > config.MaxWait {
				delay = config.MaxWait
			}
		}

		logger.L().Ctx(ctx).Debug("retrying operation after 429 rate limit",
			helpers.String("operation", operation),
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
