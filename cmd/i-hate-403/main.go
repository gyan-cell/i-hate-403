// i-hate-403: Production-grade 403/401 bypass tool for authorized penetration testing.
//
// AUTHORIZED USE ONLY. Running this tool against targets without explicit written
// permission is illegal and unethical. The authors accept no liability for misuse.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/time/rate"

	"github.com/gyan-cell/i-hate-403/internal/bypass"
	"github.com/gyan-cell/i-hate-403/internal/calibrate"
	httpclient "github.com/gyan-cell/i-hate-403/internal/http"
	"github.com/gyan-cell/i-hate-403/internal/report"
	"github.com/gyan-cell/i-hate-403/internal/score"
	"github.com/gyan-cell/i-hate-403/web"
)

// Version is the tool version, injected at build time via -ldflags.
var Version = "dev"

// cliFlags holds all CLI flag values parsed by cobra.
type cliFlags struct {
	url         string
	urlFile     string
	requestFile string
	techniques  string
	bypassIP    []string
	marker      string
	output      string
	unique      bool
	status      []int
	threads     int
	timeout     time.Duration
	proxy       string
	insecure    bool
	userAgent   string
	verbose     bool
	scope       string
	noScope     bool
	rateLimit   float64
	quick       bool
	web         bool
	webAddr     string
}

func main() {
	flags := &cliFlags{}

	root := &cobra.Command{
		Use:   "i-hate-403",
		Short: "Production-grade 403/401 bypass tool",
		Long: `i-hate-403 — Because 403 is just a suggestion.

  ╔══════════════════════════════════════════════════════════════╗
  ║  AUTHORIZED PENETRATION TESTING / BUG BOUNTY USE ONLY.     ║
  ║  Using this tool without explicit written authorization      ║
  ║  from the target owner is illegal. You have been warned.    ║
  ╚══════════════════════════════════════════════════════════════╝

Techniques: verbs, verbs-case, headers, endpaths, midpaths,
            double-encoding, unicode, path-case, http-versions,
            custom-position, raw-request`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(flags)
		},
	}

	f := root.Flags()
	f.StringVarP(&flags.url, "url", "u", "", "Target URL (e.g. https://target.tld/admin)")
	f.StringVarP(&flags.urlFile, "list", "l", "", "File containing target URLs (one per line)")
	f.StringVar(&flags.requestFile, "request-file", "", "Burp/ZAP raw HTTP request file")
	f.StringVarP(&flags.techniques, "technique", "k", "all", "Comma-separated technique names or 'all'")
	f.StringArrayVar(&flags.bypassIP, "bypass-ip", nil, "IP(s) to inject in header-based bypasses (default: internal ranges)")
	f.StringVarP(&flags.marker, "marker", "p", "§", "Payload position marker for custom-position technique")
	f.StringVarP(&flags.output, "output", "o", "", "Output file path (extension determines format: .json, .csv, .txt)")
	f.BoolVar(&flags.unique, "unique", false, "Collapse identical (status, length, hash) results")
	f.IntSliceVar(&flags.status, "status", nil, "Filter output to specific status codes (e.g. --status 200,302)")
	f.IntVarP(&flags.threads, "threads", "t", 10, "Concurrent workers per technique")
	f.DurationVar(&flags.timeout, "timeout", 10*time.Second, "Per-request timeout")
	f.StringVar(&flags.proxy, "proxy", "", "HTTP/SOCKS proxy URL (e.g. http://127.0.0.1:8080)")
	f.BoolVar(&flags.insecure, "insecure", false, "Skip TLS certificate verification")
	f.StringVar(&flags.userAgent, "user-agent", "i-hate-403/"+Version, "User-Agent string")
	f.BoolVarP(&flags.verbose, "verbose", "v", false, "Show all results including NONE confidence")
	f.StringVar(&flags.scope, "scope", "", "Restrict requests to this domain/CIDR (default: target's domain)")
	f.BoolVar(&flags.noScope, "no-scope", false, "Disable automatic scope restriction")
	f.Float64Var(&flags.rateLimit, "rate-limit", 0, "Max requests per second (0 = unlimited)")
	f.BoolVar(&flags.quick, "quick", false, "Fast preset: headers+midpaths+endpaths+verbs, single baseline check")
	f.BoolVar(&flags.web, "web", false, "Start the web UI server")
	f.StringVar(&flags.webAddr, "web-addr", "127.0.0.1:8080", "Web UI server address")

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(flags *cliFlags) error {
	if flags.web {
		return web.Start(flags.webAddr)
	}

	report.PrintBanner()

	// Collect target URLs.
	var targets []string
	if flags.url != "" {
		targets = append(targets, flags.url)
	}
	if flags.urlFile != "" {
		urls, err := readLines(flags.urlFile)
		if err != nil {
			return fmt.Errorf("reading URL file: %w", err)
		}
		targets = append(targets, urls...)
	}
	if flags.requestFile == "" && len(targets) == 0 {
		return fmt.Errorf("at least one of -u, -l, or --request-file is required")
	}

	// Build HTTP client.
	var limiter *rate.Limiter
	if flags.rateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(flags.rateLimit), 1)
	}

	clientCfg := httpclient.Config{
		Timeout:     flags.timeout,
		ProxyURL:    flags.proxy,
		Insecure:    flags.insecure,
		UserAgent:   flags.userAgent,
		RateLimiter: limiter,
	}
	hc := httpclient.NewClient(clientCfg)

	// Build technique registry.
	registry := bypass.DefaultRegistry()

	// Parse technique filter.
	techList := registry.Filter(flags.techniques)
	if flags.quick {
		techList = registry.Filter("headers,midpaths,endpaths,verbs")
	}

	// Set up graceful Ctrl+C cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n\n[!] Interrupted — flushing partial results...")
		cancel()
	}()

	// Parse raw request file if provided.
	var rawReq *bypass.RawHTTPRequest
	if flags.requestFile != "" {
		data, err := os.ReadFile(flags.requestFile)
		if err != nil {
			return fmt.Errorf("reading request file: %w", err)
		}
		rawReq, err = bypass.ParseRawRequest(data)
		if err != nil {
			return fmt.Errorf("parsing request file: %w", err)
		}
		// If no URL given, derive from Host header.
		if len(targets) == 0 && rawReq.Host != "" {
			targets = append(targets, rawReq.Scheme+"://"+rawReq.Host+rawReq.Path)
		}
	}

	// Engine config.
	engCfg := bypass.EngineConfig{
		Threads:      flags.threads,
		Timeout:      flags.timeout,
		Verbose:      flags.verbose,
		ProxyURL:     flags.proxy,
		Insecure:     flags.insecure,
		UserAgent:    flags.userAgent,
		Quick:        flags.quick,
		Unique:       flags.unique,
		StatusFilter: flags.status,
		RateLimiter:  limiter,
	}

	var allResults []score.ScoredResult

	for _, targetURL := range targets {
		results, err := processTarget(ctx, targetURL, flags, hc, registry, techList, engCfg, rawReq)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[!] Error on %s: %v\n", targetURL, err)
			continue
		}
		allResults = append(allResults, results...)
		if ctx.Err() != nil {
			break
		}
	}

	// Post-process: dedup, filter.
	if flags.unique {
		allResults = score.Dedup(allResults)
	}
	if len(flags.status) > 0 {
		var filtered []score.ScoredResult
		for _, sc := range flags.status {
			filtered = append(filtered, score.FilterByStatus(allResults, sc)...)
		}
		allResults = filtered
	}

	// Terminal output.
	report.PrintResults(allResults, flags.verbose)
	report.PrintCurlCommands(allResults)

	// File output.
	if flags.output != "" {
		if err := writeOutput(flags.output, targets[0], allResults); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Output error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\n[+] Results written to %s\n", flags.output)
		}
	}

	return nil
}

func processTarget(
	ctx context.Context,
	targetURL string,
	flags *cliFlags,
	hc *httpclient.Client,
	_ *bypass.Registry,
	techList []bypass.Technique,
	engCfg bypass.EngineConfig,
	rawReq *bypass.RawHTTPRequest,
) ([]score.ScoredResult, error) {
	// Parse target.
	target, err := bypass.ParseTarget(targetURL, flags.bypassIP, flags.marker, flags.userAgent)
	if err != nil {
		return nil, fmt.Errorf("parsing target: %w", err)
	}
	if rawReq != nil {
		target.RawRequest = rawReq
	}

	// Calibrate.
	cal := calibrate.NewCalibrator(hc.HTTPClient(), flags.verbose)
	baseline, err := cal.CaptureBaseline(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("calibration: %w", err)
	}
	report.PrintBaseline(*baseline)

	// Run engine (returns raw results).
	engine := bypass.NewEngine(engCfg, hc.HTTPClient(), *baseline, bypass.DefaultRegistry())
	rawResults, err := engine.Run(ctx, target, techList)
	if err != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("engine: %w", err)
	}

	// Score all results.
	scorer := score.NewScorer(*baseline, flags.proxy, flags.insecure)
	var results []score.ScoredResult
	for _, r := range rawResults {
		results = append(results, scorer.Score(r))
	}
	return results, nil
}

func writeOutput(path string, targetURL string, results []score.ScoredResult) error {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return report.WriteJSONFile(path, targetURL, calibrate.Baseline{}, results)
	case strings.HasSuffix(lower, ".csv"):
		return report.WriteCSVFile(path, results)
	default:
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		for _, r := range results {
			if r.Confidence == score.ConfidenceNone {
				continue
			}
			fmt.Fprintf(f, "[%s] %d | %s | %s\n",
				r.Confidence, r.StatusCode, r.Payload.TechniqueName, r.Payload.Description)
			if r.CurlCommand != "" {
				fmt.Fprintf(f, "    %s\n", r.CurlCommand)
			}
		}
		return nil
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}
