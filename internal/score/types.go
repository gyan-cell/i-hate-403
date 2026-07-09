// Package score provides heuristic confidence scoring and result deduplication.
package score

import (
	"github.com/gyan-cell/i-hate-403/internal/bypass"
)

// Confidence represents the confidence level of a bypass finding.
type Confidence string

const (
	// ConfidenceHigh indicates a strong bypass signal: status changed from blocked to
	// success, content-length differs beyond tolerance, body hash changed.
	ConfidenceHigh Confidence = "HIGH"
	// ConfidenceMedium indicates a likely bypass: status changed, body content differs.
	ConfidenceMedium Confidence = "MEDIUM"
	// ConfidenceLow indicates a possible soft-block: status changed but body nearly
	// identical to baseline (likely a soft redirect or custom error page).
	ConfidenceLow Confidence = "LOW"
	// ConfidenceInteresting indicates a notable anomaly: status unchanged but content
	// length shifted meaningfully beyond the calibration tolerance.
	ConfidenceInteresting Confidence = "INTERESTING"
	// ConfidenceNone indicates no meaningful difference from the baseline.
	ConfidenceNone Confidence = "NONE"
)

// ScoredResult is a bypass result with a heuristic confidence score attached.
type ScoredResult struct {
	// Payload is the original bypass payload that produced this result.
	Payload bypass.Payload
	// StatusCode is the HTTP response status code.
	StatusCode int
	// ContentLength is the response body size in bytes.
	ContentLength int64
	// BodyHash is the SHA-256 hex digest of the response body.
	BodyHash string
	// ContentType is the Content-Type response header value.
	ContentType string
	// ResponseTime is the request round-trip time in milliseconds.
	ResponseTime int64

	// Confidence is the heuristic confidence classification.
	Confidence Confidence
	// Score is a numeric confidence score from 0 to 100.
	Score int

	// StatusDelta is the difference between this result's status and the baseline.
	StatusDelta int
	// LengthDelta is the difference between this result's content length and the baseline.
	LengthDelta int64
	// BodyChanged is true if the body hash differs from the baseline.
	BodyChanged bool
	// TypeChanged is true if the Content-Type differs from the baseline.
	TypeChanged bool

	// CurlCommand is a replayable curl command that reproduces this finding.
	CurlCommand string

	// Count is the number of identical results (for deduplication display).
	Count int

	// Error holds any error that occurred during the request.
	Error string
}

// DedupKey is the composite key used to identify duplicate results.
type DedupKey struct {
	StatusCode    int
	ContentLength int64
	BodyHash      string
}
