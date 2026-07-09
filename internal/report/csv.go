package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"

	"github.com/gyan-cell/i-hate-403/internal/score"
)

// csvHeaders defines the column order for CSV output.
var csvHeaders = []string{
	"score",
	"confidence",
	"technique",
	"description",
	"method",
	"url",
	"status_code",
	"content_length",
	"body_hash",
	"content_type",
	"response_time_ms",
	"status_delta",
	"length_delta",
	"body_changed",
	"type_changed",
	"count",
	"curl_command",
	"error",
}

// WriteCSV writes scored results as CSV to the given writer, including a header row.
func WriteCSV(w io.Writer, results []score.ScoredResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Write header row.
	if err := cw.Write(csvHeaders); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, r := range results {
		url := r.Payload.URL
		if r.Payload.RawURL != "" {
			url = r.Payload.RawURL
		}

		record := []string{
			fmt.Sprintf("%d", r.Score),
			string(r.Confidence),
			r.Payload.TechniqueName,
			r.Payload.Description,
			r.Payload.Method,
			url,
			fmt.Sprintf("%d", r.StatusCode),
			fmt.Sprintf("%d", r.ContentLength),
			r.BodyHash,
			r.ContentType,
			fmt.Sprintf("%d", r.ResponseTime),
			fmt.Sprintf("%d", r.StatusDelta),
			fmt.Sprintf("%d", r.LengthDelta),
			fmt.Sprintf("%t", r.BodyChanged),
			fmt.Sprintf("%t", r.TypeChanged),
			fmt.Sprintf("%d", r.Count),
			r.CurlCommand,
			r.Error,
		}

		if err := cw.Write(record); err != nil {
			return fmt.Errorf("writing CSV record: %w", err)
		}
	}

	return cw.Error()
}

// WriteCSVFile writes scored results as CSV to the specified file path.
func WriteCSVFile(path string, results []score.ScoredResult) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating CSV file %q: %w", path, err)
	}
	defer f.Close()

	return WriteCSV(f, results)
}
