// Package score provides heuristic confidence scoring and result deduplication.
package score

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/gyan-cell/i-hate-403/internal/bypass"
	"github.com/gyan-cell/i-hate-403/internal/calibrate"
)

// Scorer scores bypass results against a captured baseline.
type Scorer struct {
	baseline calibrate.Baseline
	proxyURL string
	insecure bool
}

// NewScorer creates a new Scorer with the given baseline and replay options.
func NewScorer(baseline calibrate.Baseline, proxyURL string, insecure bool) *Scorer {
	return &Scorer{
		baseline: baseline,
		proxyURL: proxyURL,
		insecure: insecure,
	}
}

// Score evaluates a single bypass Result against the baseline and returns a ScoredResult
// with confidence classification and numeric score.
func (s *Scorer) Score(result bypass.Result) ScoredResult {
	sr := ScoredResult{
		Payload:       result.Payload,
		StatusCode:    result.StatusCode,
		ContentLength: result.ContentLength,
		BodyHash:      result.BodyHash,
		ContentType:   result.ContentType,
		ResponseTime:  result.ResponseTime,
		Count:         1,
	}

	// Capture any error from the request.
	if result.Error != nil {
		sr.Error = result.Error.Error()
		sr.Confidence = ConfidenceNone
		sr.Score = 0
		return sr
	}

	// Compute deltas from baseline.
	sr.StatusDelta = result.StatusCode - s.baseline.StatusCode
	sr.LengthDelta = result.ContentLength - s.baseline.ContentLength
	sr.BodyChanged = result.BodyHash != s.baseline.BodyHash
	sr.TypeChanged = result.ContentType != s.baseline.ContentType

	// Build a replayable curl command.
	sr.CurlCommand = buildCurlCommand(result.Payload, s.proxyURL, s.insecure)

	// --- Heuristic scoring engine ---
	score := 0

	baselineBlocked := isBlockedStatus(s.baseline.StatusCode)
	resultSuccess := isSuccessStatus(result.StatusCode)
	statusChanged := result.StatusCode != s.baseline.StatusCode

	// Content-length is outside the calibration tolerance band.
	lengthOutsideTolerance := isOutsideTolerance(result.ContentLength, s.baseline.Tolerance)

	// 1. Status code changed from blocked → success: strong bypass signal.
	if baselineBlocked && resultSuccess {
		score += 50
	} else if statusChanged && resultSuccess {
		score += 35
	} else if statusChanged {
		score += 15
	}

	// 2. Body hash differs from baseline.
	if sr.BodyChanged {
		score += 20
	}

	// 3. Content-length outside tolerance band.
	if lengthOutsideTolerance {
		score += 15
	}

	// 4. Content-Type changed.
	if sr.TypeChanged {
		score += 10
	}

	// 5. Penalty for soft-404 detection: if calibration detected soft-404s and
	//    the result is 200 with body matching the baseline, it's likely a soft redirect.
	if s.baseline.Tolerance.SoftNotFound && result.StatusCode == 200 && !sr.BodyChanged {
		score -= 25
	}

	// 6. Penalty if status worsened (e.g., 403 → 500 is not a bypass).
	if result.StatusCode >= 500 {
		score -= 10
	}

	// Clamp score to [0, 100].
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	sr.Score = score

	// Classify confidence from the numeric score.
	sr.Confidence = classifyConfidence(score, statusChanged, sr.BodyChanged, lengthOutsideTolerance)

	return sr
}

// ScoreBatch scores a slice of results and returns them sorted by score descending.
func (s *Scorer) ScoreBatch(results []bypass.Result) []ScoredResult {
	scored := make([]ScoredResult, 0, len(results))
	for _, r := range results {
		scored = append(scored, s.Score(r))
	}
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})
	return scored
}

// classifyConfidence maps a numeric score and delta flags to a Confidence level.
func classifyConfidence(score int, statusChanged, bodyChanged, lengthOutside bool) Confidence {
	switch {
	case score >= 60:
		return ConfidenceHigh
	case score >= 40:
		return ConfidenceMedium
	case score >= 25:
		return ConfidenceLow
	case score >= 10 && (lengthOutside || bodyChanged):
		return ConfidenceInteresting
	default:
		return ConfidenceNone
	}
}

// isBlockedStatus returns true if the status code indicates a blocked request.
func isBlockedStatus(code int) bool {
	switch code {
	case 401, 403, 405, 407, 423, 451:
		return true
	default:
		return false
	}
}

// isSuccessStatus returns true if the status code indicates a successful response.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// isOutsideTolerance checks if a content-length falls outside the calibration tolerance band.
func isOutsideTolerance(length int64, tol calibrate.ToleranceBand) bool {
	if tol.Samples == 0 {
		return false
	}
	fl := float64(length)
	return fl < tol.Min || fl > tol.Max
}

// buildCurlCommand constructs a reproducible curl command for a bypass payload.
func buildCurlCommand(p bypass.Payload, proxyURL string, insecure bool) string {
	var parts []string
	parts = append(parts, "curl")

	if insecure {
		parts = append(parts, "-k")
	}

	if proxyURL != "" {
		parts = append(parts, "-x", shellEscape(proxyURL))
	}

	if p.Method != "" && p.Method != "GET" {
		parts = append(parts, "-X", p.Method)
	}

	for k, v := range p.Headers {
		parts = append(parts, "-H", shellEscape(fmt.Sprintf("%s: %s", k, v)))
	}

	if p.Body != "" {
		parts = append(parts, "-d", shellEscape(p.Body))
	}

	if len(p.CurlArgs) > 0 {
		parts = append(parts, p.CurlArgs...)
	}

	parts = append(parts, "-s", "-o", "/dev/null", "-w",
		shellEscape("%{http_code} %{size_download}"))

	targetURL := p.URL
	if p.RawURL != "" {
		targetURL = p.RawURL
	}
	parts = append(parts, shellEscape(targetURL))

	return strings.Join(parts, " ")
}

// shellEscape wraps a string in single quotes, escaping embedded single quotes.
func shellEscape(s string) string {
	if s == "" {
		return "''"
	}
	// Check if simple quoting is sufficient (no special chars).
	safe := true
	for _, c := range s {
		if c == ' ' || c == '\'' || c == '"' || c == '\\' || c == '$' ||
			c == '!' || c == '`' || c == '(' || c == ')' || c == '{' ||
			c == '}' || c == '[' || c == ']' || c == '|' || c == '&' ||
			c == ';' || c == '<' || c == '>' || c == '~' || c == '#' ||
			c == '*' || c == '?' || c == '\n' || c == '\t' {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// abs returns the absolute value of a float64.
func abs(x float64) float64 {
	return math.Abs(x)
}
