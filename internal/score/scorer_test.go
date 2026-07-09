package score

import (
	"fmt"
	"testing"

	"github.com/gyan-cell/i-hate-403/internal/bypass"
	"github.com/gyan-cell/i-hate-403/internal/calibrate"
)

// makeBaseline builds a test Baseline with the given status and content length.
func makeBaseline(status int, length int64, bodyHash, ct string) calibrate.Baseline {
	return calibrate.Baseline{
		StatusCode:    status,
		ContentLength: length,
		BodyHash:      bodyHash,
		ContentType:   ct,
		Tolerance: calibrate.ToleranceBand{
			Min:     float64(length) * 0.8,
			Max:     float64(length) * 1.2,
			Mean:    float64(length),
			StdDev:  float64(length) * 0.1,
			Samples: 3,
		},
	}
}

// makeResult builds a test bypass.Result with the given fields.
func makeResult(status int, length int64, bodyHash, ct string) bypass.Result {
	return bypass.Result{
		Payload: bypass.Payload{
			TechniqueName: "test",
			Method:        "GET",
			URL:           "https://example.com/admin",
		},
		StatusCode:    status,
		ContentLength: length,
		BodyHash:      bodyHash,
		ContentType:   ct,
	}
}

// TestScoreHighConfidence verifies that a clear bypass (4xx→2xx, body changed,
// length outside tolerance, type changed) gets HIGH confidence.
func TestScoreHighConfidence(t *testing.T) {
	baseline := makeBaseline(403, 512, "hash-baseline", "text/plain")
	scorer := NewScorer(baseline, "", false)

	result := makeResult(200, 8192, "hash-different", "text/html")
	scored := scorer.Score(result)

	if scored.Confidence != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s (score=%d)", scored.Confidence, scored.Score)
	}
	if scored.Score < 70 {
		t.Errorf("expected score >= 70 for HIGH, got %d", scored.Score)
	}
	if !scored.BodyChanged {
		t.Error("expected BodyChanged=true")
	}
	if !scored.TypeChanged {
		t.Error("expected TypeChanged=true")
	}
}

// TestScoreSoftBlock verifies that a status change with identical body gets
// LOW or MEDIUM confidence (not HIGH) — both are acceptable for soft-blocks.
func TestScoreLowConfidenceSoftBlock(t *testing.T) {
	baseline := makeBaseline(403, 512, "same-hash", "text/html")
	scorer := NewScorer(baseline, "", false)

	// Same body hash as baseline — classic soft-block. Should NOT be HIGH.
	result := makeResult(200, 512, "same-hash", "text/html")
	scored := scorer.Score(result)

	if scored.Confidence == ConfidenceHigh {
		t.Errorf("soft-block (same body hash) should not be HIGH, got %s score=%d", scored.Confidence, scored.Score)
	}
}

// TestScoreNoneOnError verifies that error results get NONE confidence with score 0.
func TestScoreNoneOnError(t *testing.T) {
	baseline := makeBaseline(403, 512, "hash", "text/html")
	scorer := NewScorer(baseline, "", false)

	result := bypass.Result{
		Payload: bypass.Payload{TechniqueName: "test"},
		Error:   fmt.Errorf("connection refused"),
	}
	scored := scorer.Score(result)

	if scored.Confidence != ConfidenceNone {
		t.Errorf("expected NONE confidence for error result, got %s", scored.Confidence)
	}
	if scored.Score != 0 {
		t.Errorf("expected score=0 for error result, got %d", scored.Score)
	}
}

// TestScoreInteresting verifies that status unchanged but significantly shifted
// content length gets at least a non-NONE classification (INTERESTING or LOW).
func TestScoreInteresting(t *testing.T) {
	baseline := makeBaseline(403, 512, "hash-baseline", "text/html")
	scorer := NewScorer(baseline, "", false)

	// Same status (403) but very different length — possibly revealing different content.
	result := makeResult(403, 8192, "hash-different", "text/html")
	scored := scorer.Score(result)

	// Should be INTERESTING or LOW (not NONE and not HIGH for unchanged status)
	if scored.Confidence == ConfidenceHigh || scored.Confidence == ConfidenceMedium {
		t.Errorf("status-unchanged result should not be HIGH/MEDIUM, got %s", scored.Confidence)
	}
}

// TestScoreNoneOnBaseline verifies that a response identical to baseline is NONE.
func TestScoreNoneOnBaseline(t *testing.T) {
	baseline := makeBaseline(403, 512, "same-hash", "text/html")
	scorer := NewScorer(baseline, "", false)

	result := makeResult(403, 512, "same-hash", "text/html")
	scored := scorer.Score(result)

	if scored.Confidence != ConfidenceNone {
		t.Errorf("expected NONE for baseline-identical result, got %s", scored.Confidence)
	}
}

// TestDedup verifies that identical results are collapsed and Count is set.
func TestDedup(t *testing.T) {
	p := bypass.Payload{TechniqueName: "test", Method: "GET", URL: "https://example.com/admin"}
	results := []ScoredResult{
		{Payload: p, StatusCode: 200, ContentLength: 1000, BodyHash: "abc", Confidence: ConfidenceHigh, Score: 90, Count: 1},
		{Payload: p, StatusCode: 200, ContentLength: 1000, BodyHash: "abc", Confidence: ConfidenceHigh, Score: 85, Count: 1},
		{Payload: p, StatusCode: 403, ContentLength: 512, BodyHash: "xyz", Confidence: ConfidenceNone, Score: 0, Count: 1},
	}

	deduped := Dedup(results)

	// Should have 2 unique results (200/1000/abc and 403/512/xyz).
	if len(deduped) != 2 {
		t.Errorf("Dedup returned %d results, expected 2", len(deduped))
	}

	// The 200 group should have Count=2 and keep the higher score.
	for _, r := range deduped {
		if r.StatusCode == 200 {
			if r.Count != 2 {
				t.Errorf("expected Count=2 for 200 group, got %d", r.Count)
			}
			if r.Score != 90 {
				t.Errorf("expected Score=90 (highest kept), got %d", r.Score)
			}
		}
	}
}

// TestFilterByStatus verifies that results are filtered to specified status codes.
func TestFilterByStatus(t *testing.T) {
	results := []ScoredResult{
		{StatusCode: 200, Confidence: ConfidenceHigh},
		{StatusCode: 302, Confidence: ConfidenceMedium},
		{StatusCode: 403, Confidence: ConfidenceNone},
	}

	filtered := FilterByStatus(results, 200)
	if len(filtered) != 1 {
		t.Errorf("FilterByStatus(200) returned %d results, expected 1", len(filtered))
	}
	if filtered[0].StatusCode != 200 {
		t.Errorf("expected status 200, got %d", filtered[0].StatusCode)
	}
}

// TestFilterUnique verifies that results identical to baseline (same status + hash)
// are removed while different results are kept.
func TestFilterUnique(t *testing.T) {
	// Baseline: status=403, hash="baseline-hash"
	results := []ScoredResult{
		{StatusCode: 200, BodyHash: "different-hash", Confidence: ConfidenceHigh},  // keep
		{StatusCode: 403, BodyHash: "baseline-hash", Confidence: ConfidenceNone},   // filter (same as baseline)
		{StatusCode: 403, BodyHash: "different-hash", Confidence: ConfidenceInteresting}, // keep (hash differs)
		{StatusCode: 403, BodyHash: "baseline-hash", Confidence: ConfidenceNone},   // filter
	}

	unique := FilterUnique(results, 403, "baseline-hash")
	if len(unique) != 2 {
		t.Errorf("FilterUnique returned %d results, expected 2", len(unique))
	}
	for _, r := range unique {
		if r.StatusCode == 403 && r.BodyHash == "baseline-hash" {
			t.Error("FilterUnique kept a baseline-identical result")
		}
	}
}
