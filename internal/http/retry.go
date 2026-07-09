package httpclient

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"
)

// RetryConfig controls retry behavior for transient failures.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (not counting the initial request).
	MaxRetries int
	// InitialBackoff is the base duration before the first retry.
	InitialBackoff time.Duration
	// MaxBackoff caps the maximum wait between retries.
	MaxBackoff time.Duration
}

// DefaultRetryConfig returns a sensible default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 500 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
	}
}

// DoWithRetry executes a request with automatic retries on transient failures.
// It retries on timeouts, connection resets, and server errors (429, 502, 503, 504).
// Exponential backoff with jitter is applied between attempts.
func DoWithRetry(ctx context.Context, client *Client, req *http.Request, cfg RetryConfig) (*http.Response, error) {
	var lastErr error
	var resp *http.Response

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		// Wait with backoff before retrying (skip on first attempt).
		if attempt > 0 {
			backoff := computeBackoff(attempt, cfg.InitialBackoff, cfg.MaxBackoff)
			if err := sleepWithContext(ctx, backoff); err != nil {
				return nil, fmt.Errorf("retry backoff interrupted: %w", err)
			}
		}

		var err error
		resp, err = client.Do(ctx, req)
		if err != nil {
			lastErr = err
			if !isRetriableError(err) {
				return nil, fmt.Errorf("non-retriable error on attempt %d: %w", attempt+1, err)
			}
			continue
		}

		// Check for retriable HTTP status codes.
		if isRetriableStatus(resp.StatusCode) {
			lastErr = fmt.Errorf("retriable status %d on attempt %d", resp.StatusCode, attempt+1)
			// Drain and close body to allow connection reuse.
			resp.Body.Close()
			continue
		}

		// Success — return the response.
		return resp, nil
	}

	return nil, fmt.Errorf("all %d retries exhausted: %w", cfg.MaxRetries+1, lastErr)
}

// isRetriableError checks whether an error is transient and worth retrying.
func isRetriableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for context cancellation — not retriable.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Network timeout errors.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Connection reset / refused.
	errMsg := err.Error()
	if strings.Contains(errMsg, "connection reset") ||
		strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "EOF") {
		return true
	}

	return false
}

// isRetriableStatus returns true for HTTP status codes that indicate a
// transient server-side issue worth retrying.
func isRetriableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,     // 429
		http.StatusBadGateway,           // 502
		http.StatusServiceUnavailable,   // 503
		http.StatusGatewayTimeout:       // 504
		return true
	default:
		return false
	}
}

// computeBackoff calculates the wait duration for a given retry attempt using
// exponential backoff with full jitter.
func computeBackoff(attempt int, initial, max time.Duration) time.Duration {
	// Exponential: initial * 2^(attempt-1), capped at max.
	backoff := float64(initial) * math.Pow(2, float64(attempt-1))
	if backoff > float64(max) {
		backoff = float64(max)
	}

	// Full jitter: random duration in [0, backoff].
	jittered := time.Duration(rand.Int64N(int64(backoff) + 1))
	return jittered
}

// sleepWithContext pauses for the given duration but returns early if the
// context is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled during sleep: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}
