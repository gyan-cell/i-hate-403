// Package web provides the embedded HTTP server with SSE streaming for the
// i-hate-403 web UI. It exposes a POST /api/scan endpoint that streams bypass
// results in real time via Server-Sent Events.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gyan-cell/i-hate-403/internal/bypass"
	"github.com/gyan-cell/i-hate-403/internal/calibrate"
	httpclient "github.com/gyan-cell/i-hate-403/internal/http"
	"github.com/gyan-cell/i-hate-403/internal/score"
)

//go:embed static
var staticFiles embed.FS

// scanRequest mirrors the JSON body accepted by /api/scan.
type scanRequest struct {
	URL      string            `json:"url"`
	Path     string            `json:"path"`
	Workers  int               `json:"workers"`
	Timeout  int               `json:"timeout"`
	Insecure bool              `json:"insecure"`
	Proxy    string            `json:"proxy"`
	Filter   []string          `json:"filter"`
	Headers  map[string]string `json:"headers"`
}

// scanEvent is the SSE event payload sent to the client.
type scanEvent struct {
	Type    string              `json:"type"` // "start", "baseline", "result", "done", "error"
	Total   int                 `json:"total,omitempty"`
	Scanned int                 `json:"scanned,omitempty"`
	Result  *webResult          `json:"result,omitempty"`
	Message string              `json:"message,omitempty"`
	Elapsed string              `json:"elapsed,omitempty"`
}

// webResult is the flattened per-result object the browser receives.
type webResult struct {
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	ResponseTime  int64  `json:"response_time_ms"`
	ContentType   string `json:"content_type"`
	BodyChanged   bool   `json:"body_changed"`
	Confidence    string `json:"confidence"`
	Score         int    `json:"score"`
	Bypassed      bool   `json:"bypassed"`
	TechniqueName string `json:"technique"`
	Description   string `json:"description"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	Category      string `json:"category"`
	CurlCommand   string `json:"curl,omitempty"`
	Error         string `json:"error,omitempty"`
}

func getCategory(tech string, desc string) string {
	switch tech {
	case "verbs", "verbs-case", "http-versions":
		return "Method"
	case "headers":
		descLower := strings.ToLower(desc)
		if strings.Contains(descLower, "ip") || strings.Contains(descLower, "forwarded-for") || strings.Contains(descLower, "real-ip") {
			return "IP Spoof"
		}
		return "Headers"
	case "endpaths", "midpaths", "double-encoding", "unicode", "path-case", "custom-position":
		return "Path"
	default:
		return "Path"
	}
}

func toWebResult(sr score.ScoredResult) *webResult {
	return &webResult{
		StatusCode:    sr.StatusCode,
		ContentLength: sr.ContentLength,
		ResponseTime:  sr.ResponseTime,
		ContentType:   sr.ContentType,
		BodyChanged:   sr.BodyChanged,
		Confidence:    string(sr.Confidence),
		Score:         sr.Score,
		Bypassed:      sr.Confidence == score.ConfidenceHigh || sr.Confidence == score.ConfidenceMedium,
		TechniqueName: sr.Payload.TechniqueName,
		Description:   sr.Payload.Description,
		Method:        sr.Payload.Method,
		URL:           sr.Payload.URL,
		Category:      getCategory(sr.Payload.TechniqueName, sr.Payload.Description),
		CurlCommand:   sr.CurlCommand,
		Error:         sr.Error,
	}
}

// Start launches the web UI server on the given address.
func Start(addr string) error {
	staticSub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("embedding static files: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticSub)))
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/scan", scanHandler)

	fmt.Printf("[+] Web UI → http://%s\n", addr)
	fmt.Println("[+] Press Ctrl+C to stop.")
	return http.ListenAndServe(addr, corsMiddleware(mux))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "url is required", http.StatusBadRequest)
		return
	}
	if req.Workers <= 0 {
		req.Workers = 10
	}
	if req.Timeout <= 0 {
		req.Timeout = 10
	}

	// SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// sendSSE writes a proper SSE event: "event: <type>\ndata: <json>\n\n"
	sendSSE := func(evt scanEvent) {
		data, _ := json.Marshal(evt)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
		flusher.Flush()
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	timeout := time.Duration(req.Timeout) * time.Second
	clientCfg := httpclient.Config{
		Timeout:   timeout,
		Insecure:  req.Insecure,
		ProxyURL:  req.Proxy,
		UserAgent: "i-hate-403-web/dev",
	}
	hc := httpclient.NewClient(clientCfg)

	targetURL := req.URL
	if req.Path != "" {
		if strings.HasSuffix(targetURL, "/") && strings.HasPrefix(req.Path, "/") {
			targetURL = targetURL + req.Path[1:]
		} else if !strings.HasSuffix(targetURL, "/") && !strings.HasPrefix(req.Path, "/") {
			targetURL = targetURL + "/" + req.Path
		} else {
			targetURL = targetURL + req.Path
		}
	}

	// Calibrate.
	cal := calibrate.NewCalibrator(hc.HTTPClient(), req.Insecure)
	baseline, err := cal.CaptureBaseline(ctx, "GET", targetURL, req.Headers)
	if err != nil {
		errMsg := err.Error()
		hint := ""
		switch {
		case strings.Contains(errMsg, "deadline exceeded") || strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "connection timed out"):
			hint = " — Target is unreachable or too slow. Try: increase Timeout, add a Proxy URL (e.g. http://127.0.0.1:8080), or check your VPN/network."
		case strings.Contains(errMsg, "connection refused"):
			hint = " — Connection refused. The server is up but rejecting connections on this port."
		case strings.Contains(errMsg, "no such host") || strings.Contains(errMsg, "dial tcp: lookup"):
			hint = " — DNS resolution failed. Check the URL spelling or your network/DNS settings."
		case strings.Contains(errMsg, "certificate") || strings.Contains(errMsg, "x509"):
			hint = " — TLS certificate error. Enable 'Skip TLS Verify' in the settings."
		}
		sendSSE(scanEvent{Type: "error", Message: fmt.Sprintf("calibration failed: %v%s", err, hint)})
		return
	}

	fp := ""
	if baseline.Fingerprint != nil {
		fp = baseline.Fingerprint.String()
	}
	sendSSE(scanEvent{Type: "baseline", Message: fmt.Sprintf(
		"status=%d length=%d fingerprint=%s",
		baseline.StatusCode, baseline.ContentLength, fp,
	)})

	// Parse target.
	target, err := bypass.ParseTarget(targetURL, nil, "§", clientCfg.UserAgent)
	if err != nil {
		sendSSE(scanEvent{Type: "error", Message: fmt.Sprintf("invalid URL: %v", err)})
		return
	}

	// Build techniques.
	registry := bypass.DefaultRegistry()
	var techNames []string
	for _, cat := range req.Filter {
		switch cat {
		case "Headers":
			techNames = append(techNames, "headers", "custom-position", "raw-request")
		case "Path":
			techNames = append(techNames, "endpaths", "midpaths", "double-encoding", "unicode", "path-case")
		case "Method":
			techNames = append(techNames, "verbs", "verbs-case", "http-versions")
		case "IP Spoof":
			found := false
			for _, name := range techNames {
				if name == "headers" {
					found = true
					break
				}
			}
			if !found {
				techNames = append(techNames, "headers")
			}
		}
	}
	filter := strings.Join(techNames, ",")
	if len(req.Filter) == 0 {
		filter = "all"
	}
	techList := registry.Filter(filter)

	// Count total payloads upfront for the progress bar.
	totalPayloads := 0
	for _, t := range techList {
		totalPayloads += len(t.Generate(target))
	}

	sendSSE(scanEvent{
		Type:    "start",
		Total:   totalPayloads,
		Message: fmt.Sprintf("Running %d technique(s), ~%d payloads", len(techList), totalPayloads),
	})

	// Run engine with real-time SSE streaming.
	scorer := score.NewScorer(*baseline, "", req.Insecure)
	resultStream := make(chan score.ScoredResult, 100)
	doneCh := make(chan struct{})
	start := time.Now()

	var scannedCount int
	go func() {
		defer close(doneCh)
		for sr := range resultStream {
			scannedCount++
			sendSSE(scanEvent{
				Type:    "result",
				Scanned: scannedCount,
				Total:   totalPayloads,
				Result:  toWebResult(sr),
				Elapsed: time.Since(start).Round(time.Millisecond).String(),
			})
		}
	}()

	var mu sync.Mutex
	engCfg := bypass.EngineConfig{
		Threads:   req.Workers,
		Timeout:   timeout,
		Insecure:  req.Insecure,
		UserAgent: clientCfg.UserAgent,
		OnResult: func(raw bypass.Result) {
			sr := scorer.Score(raw)
			mu.Lock()
			select {
			case resultStream <- sr:
			case <-ctx.Done():
			}
			mu.Unlock()
		},
	}
	engine := bypass.NewEngine(engCfg, hc.HTTPClient(), *baseline, registry)

	_, err = engine.Run(ctx, target, techList)
	close(resultStream)
	<-doneCh

	if err != nil && ctx.Err() == nil {
		sendSSE(scanEvent{Type: "error", Message: fmt.Sprintf("engine error: %v", err)})
		return
	}

	sendSSE(scanEvent{
		Type:    "done",
		Scanned: scannedCount,
		Total:   totalPayloads,
		Elapsed: time.Since(start).Round(time.Millisecond).String(),
	})
}

// corsMiddleware adds permissive CORS headers for local development.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
