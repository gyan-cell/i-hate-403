// Package report provides output formatting for i-hate-403 results in
// terminal, JSON, and CSV formats.
package report

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/gyan-cell/i-hate-403/internal/calibrate"
	"github.com/gyan-cell/i-hate-403/internal/score"
)

// Terminal color printers.
var (
	cBanner     = color.New(color.FgHiRed, color.Bold)
	cTagline    = color.New(color.FgHiWhite, color.Italic)
	cHeader     = color.New(color.FgHiCyan, color.Bold)
	cHigh       = color.New(color.FgHiGreen, color.Bold)
	cMedium     = color.New(color.FgHiYellow, color.Bold)
	cLow        = color.New(color.FgYellow)
	cInterest   = color.New(color.FgHiBlue)
	cNone       = color.New(color.FgWhite)
	cDim        = color.New(color.FgHiBlack)
	cError      = color.New(color.FgHiRed)
	cLabel      = color.New(color.FgCyan)
	cValue      = color.New(color.FgHiWhite)
	cSuccess    = color.New(color.FgHiGreen)
	cSeparator  = color.New(color.FgHiBlack)
)

// PrintBanner prints the i-hate-403 ASCII art banner.
func PrintBanner() {
	banner := `
  _ _           _          _  _    ___ ____  
 (_) |         | |        | || |  / _ \___ \ 
  _| |__   __ _| |_ ___   | || |_| | | |__) |
 | | '_ \ / _` + "`" + ` | __/ _ \  |__   _| | | |__ < 
 | | | | | (_| | ||  __/     | | | |_| |__) |
 |_|_| |_|\__,_|\__\___|     |_|  \___/____/ 
`
	cBanner.Fprint(os.Stderr, banner)
	cTagline.Fprintln(os.Stderr, "  ╰─ because 403 is just a suggestion ─╯")
	cDim.Fprintln(os.Stderr, "  For authorized penetration testing only.")
}

// PrintBaseline prints baseline calibration info with colors.
func PrintBaseline(b calibrate.Baseline) {
	cHeader.Fprintln(os.Stderr, "━━━ Baseline ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	printField("Status", fmt.Sprintf("%d", b.StatusCode))
	printField("Content-Length", fmt.Sprintf("%d", b.ContentLength))
	printField("Content-Type", b.ContentType)
	printField("Body Hash", truncateHash(b.BodyHash))

	if b.Tolerance.Samples > 0 {
		printField("Tolerance Band",
			fmt.Sprintf("%.0f – %.0f (μ=%.0f σ=%.1f, n=%d)",
				b.Tolerance.Min, b.Tolerance.Max,
				b.Tolerance.Mean, b.Tolerance.StdDev,
				b.Tolerance.Samples))
		if b.Tolerance.SoftNotFound {
			cError.Fprintln(os.Stderr, "  ⚠  Soft-404 detected (server returns 200 for non-existent paths)")
		}
	}

	if b.FragmentStripped {
		cDim.Fprintln(os.Stderr, "  ℹ  Server strips URL fragments")
	}

	if b.Fingerprint != nil {
		printField("Fingerprint", b.Fingerprint.String())
	}

	cSeparator.Fprintln(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintln(os.Stderr)
}

// PrintResults prints scored results in a formatted table with color-coded confidence.
func PrintResults(results []score.ScoredResult, verbose bool) {
	if len(results) == 0 {
		cDim.Fprintln(os.Stderr, "No results to display.")
		return
	}

	cHeader.Fprintln(os.Stderr, "━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	// Header row.
	cDim.Fprintf(w, "SCORE\tCONF\tSTATUS\tLENGTH\tΔ-LEN\tTECHNIQUE\tDESCRIPTION")
	if verbose {
		cDim.Fprintf(w, "\tBODY-Δ\tTYPE-Δ\tTIME(ms)")
	}
	fmt.Fprintln(w)

	for _, r := range results {
		if !verbose && r.Confidence == score.ConfidenceNone {
			continue
		}

		printer := confidencePrinter(r.Confidence)

		// Error row.
		if r.Error != "" {
			cError.Fprintf(w, "%d\t%s\t—\t—\t—\t%s\t%s",
				r.Score, r.Confidence, r.Payload.TechniqueName, r.Error)
			fmt.Fprintln(w)
			continue
		}

		countSuffix := ""
		if r.Count > 1 {
			countSuffix = fmt.Sprintf(" (×%d)", r.Count)
		}

		printer.Fprintf(w, "%d\t%s\t%d\t%d\t%+d\t%s\t%s%s",
			r.Score, r.Confidence,
			r.StatusCode, r.ContentLength, r.LengthDelta,
			r.Payload.TechniqueName, r.Payload.Description, countSuffix)

		if verbose {
			bodyDelta := "—"
			if r.BodyChanged {
				bodyDelta = "✓"
			}
			typeDelta := "—"
			if r.TypeChanged {
				typeDelta = "✓"
			}
			printer.Fprintf(w, "\t%s\t%s\t%d", bodyDelta, typeDelta, r.ResponseTime)
		}

		fmt.Fprintln(w)
	}

	w.Flush()
	cSeparator.Fprintln(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// PrintCurlCommands prints the curl replay commands for results with non-NONE confidence.
func PrintCurlCommands(results []score.ScoredResult) {
	printed := false
	for _, r := range results {
		if r.Confidence == score.ConfidenceNone || r.CurlCommand == "" {
			continue
		}
		if !printed {
			fmt.Fprintln(os.Stderr)
			cHeader.Fprintln(os.Stderr, "━━━ Curl Replay Commands ━━━━━━━━━━━━━━━━━━━━━")
			printed = true
		}

		printer := confidencePrinter(r.Confidence)
		printer.Fprintf(os.Stderr, "# [%s] %s – %s\n",
			r.Confidence, r.Payload.TechniqueName, r.Payload.Description)
		fmt.Fprintln(os.Stdout, r.CurlCommand)
	}

	if printed {
		cSeparator.Fprintln(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}
}

// confidencePrinter returns the color printer for a confidence level.
func confidencePrinter(c score.Confidence) *color.Color {
	switch c {
	case score.ConfidenceHigh:
		return cHigh
	case score.ConfidenceMedium:
		return cMedium
	case score.ConfidenceLow:
		return cLow
	case score.ConfidenceInteresting:
		return cInterest
	default:
		return cNone
	}
}

// printField prints a label: value pair with colors.
func printField(label, value string) {
	cLabel.Fprintf(os.Stderr, "  %-18s ", label+":")
	cValue.Fprintln(os.Stderr, value)
}

// truncateHash returns the first 16 characters of a hash for display.
func truncateHash(hash string) string {
	if len(hash) > 16 {
		return hash[:16] + "…"
	}
	return hash
}
