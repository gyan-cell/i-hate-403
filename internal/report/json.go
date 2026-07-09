package report

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/gyan-cell/i-hate-403/internal/calibrate"
	"github.com/gyan-cell/i-hate-403/internal/score"
)

// JSONReport is the top-level structure for JSON output.
type JSONReport struct {
	Tool      string          `json:"tool"`
	Version   string          `json:"version"`
	Timestamp string          `json:"timestamp"`
	TargetURL string          `json:"target_url"`
	Baseline  BaselineSummary `json:"baseline"`
	Summary   ReportSummary   `json:"summary"`
	Findings  []JSONFinding   `json:"findings"`
}

// BaselineSummary is the baseline info included in the JSON report.
type BaselineSummary struct {
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	ContentType   string `json:"content_type"`
	BodyHash      string `json:"body_hash"`
	ToleranceMin  float64 `json:"tolerance_min"`
	ToleranceMax  float64 `json:"tolerance_max"`
	SoftNotFound  bool   `json:"soft_not_found"`
	Fingerprint   string `json:"fingerprint,omitempty"`
}

// JSONFinding represents a single scored result in the JSON report.
type JSONFinding struct {
	Technique     string `json:"technique"`
	Description   string `json:"description"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	BodyHash      string `json:"body_hash"`
	ContentType   string `json:"content_type"`
	ResponseTime  int64  `json:"response_time_ms"`
	Confidence    string `json:"confidence"`
	Score         int    `json:"score"`
	StatusDelta   int    `json:"status_delta"`
	LengthDelta   int64  `json:"length_delta"`
	BodyChanged   bool   `json:"body_changed"`
	TypeChanged   bool   `json:"type_changed"`
	CurlCommand   string `json:"curl_command,omitempty"`
	Count         int    `json:"count"`
	Error         string `json:"error,omitempty"`
}

// ReportSummary provides aggregate statistics for the report.
type ReportSummary struct {
	TotalPayloads int `json:"total_payloads"`
	HighConf      int `json:"high_confidence"`
	MediumConf    int `json:"medium_confidence"`
	LowConf       int `json:"low_confidence"`
	Interesting   int `json:"interesting"`
}

// WriteJSON writes a full JSON report to the given writer.
func WriteJSON(w io.Writer, targetURL string, baseline calibrate.Baseline, results []score.ScoredResult) error {
	report := buildJSONReport(targetURL, baseline, results)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteJSONFile writes a full JSON report to the specified file path.
func WriteJSONFile(path string, targetURL string, baseline calibrate.Baseline, results []score.ScoredResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return WriteJSON(f, targetURL, baseline, results)
}

// buildJSONReport constructs a JSONReport from the baseline and scored results.
func buildJSONReport(targetURL string, baseline calibrate.Baseline, results []score.ScoredResult) JSONReport {
	fingerprint := ""
	if baseline.Fingerprint != nil {
		fingerprint = baseline.Fingerprint.String()
	}

	summary := ReportSummary{
		TotalPayloads: len(results),
	}

	findings := make([]JSONFinding, 0, len(results))
	for _, r := range results {
		switch r.Confidence {
		case score.ConfidenceHigh:
			summary.HighConf++
		case score.ConfidenceMedium:
			summary.MediumConf++
		case score.ConfidenceLow:
			summary.LowConf++
		case score.ConfidenceInteresting:
			summary.Interesting++
		}

		url := r.Payload.URL
		if r.Payload.RawURL != "" {
			url = r.Payload.RawURL
		}

		findings = append(findings, JSONFinding{
			Technique:     r.Payload.TechniqueName,
			Description:   r.Payload.Description,
			Method:        r.Payload.Method,
			URL:           url,
			StatusCode:    r.StatusCode,
			ContentLength: r.ContentLength,
			BodyHash:      r.BodyHash,
			ContentType:   r.ContentType,
			ResponseTime:  r.ResponseTime,
			Confidence:    string(r.Confidence),
			Score:         r.Score,
			StatusDelta:   r.StatusDelta,
			LengthDelta:   r.LengthDelta,
			BodyChanged:   r.BodyChanged,
			TypeChanged:   r.TypeChanged,
			CurlCommand:   r.CurlCommand,
			Count:         r.Count,
			Error:         r.Error,
		})
	}

	return JSONReport{
		Tool:      "i-hate-403",
		Version:   "1.0.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		TargetURL: targetURL,
		Baseline: BaselineSummary{
			StatusCode:    baseline.StatusCode,
			ContentLength: baseline.ContentLength,
			ContentType:   baseline.ContentType,
			BodyHash:      baseline.BodyHash,
			ToleranceMin:  baseline.Tolerance.Min,
			ToleranceMax:  baseline.Tolerance.Max,
			SoftNotFound:  baseline.Tolerance.SoftNotFound,
			Fingerprint:   fingerprint,
		},
		Summary:  summary,
		Findings: findings,
	}
}
