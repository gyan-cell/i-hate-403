// Package bypass provides the concurrent bypass engine that orchestrates
// technique execution with worker pools and per-technique progress bars.
package bypass

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gyan-cell/i-hate-403/internal/calibrate"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

// EngineConfig holds configuration for the bypass engine.
type EngineConfig struct {
	// Threads is the number of concurrent workers per technique.
	Threads int
	// Timeout is the per-request timeout.
	Timeout time.Duration
	// Verbose enables verbose output including NONE-confidence results.
	Verbose bool
	// ProxyURL is the HTTP/SOCKS proxy to use. Empty means no proxy.
	ProxyURL string
	// Insecure disables TLS certificate verification.
	Insecure bool
	// UserAgent is sent with every request.
	UserAgent string
	// Quick enables fast preset (fewer calibrations, selected techniques).
	Quick bool
	// Unique collapses identical results.
	Unique bool
	// StatusFilter limits results to specific status codes. Empty = all.
	StatusFilter []int
	// RateLimiter throttles outbound requests. Nil = unlimited.
	RateLimiter *rate.Limiter
}

// Engine orchestrates concurrent bypass technique execution.
type Engine struct {
	config   EngineConfig
	client   *http.Client
	baseline calibrate.Baseline
	registry *Registry
}

// NewEngine creates a new Engine.
func NewEngine(cfg EngineConfig, client *http.Client, baseline calibrate.Baseline, registry *Registry) *Engine {
	return &Engine{
		config:   cfg,
		client:   client,
		baseline: baseline,
		registry: registry,
	}
}

// Run executes all given techniques against the target, collecting every raw
// Result. Scoring is done by the caller (main) to avoid circular imports.
// It respects ctx cancellation for graceful Ctrl+C shutdown.
// On cancellation, any results collected so far are returned along with the
// context error.
func (e *Engine) Run(ctx context.Context, target *Target, techniques []Technique) ([]Result, error) {

	var (
		mu         sync.Mutex
		allResults []Result
	)

	for _, tech := range techniques {
		select {
		case <-ctx.Done():
			return allResults, ctx.Err()
		default:
		}

		payloads := tech.Generate(target)
		if len(payloads) == 0 {
			continue
		}

		// Per-technique progress bar on stderr.
		bar := progressbar.NewOptions(len(payloads),
			progressbar.OptionSetDescription(fmt.Sprintf("[cyan][%-20s][reset]", tech.Name())),
			progressbar.OptionSetWriter(io.Discard), // suppress in non-verbose mode initially
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]█[reset]",
				SaucerHead:    "[green]▶[reset]",
				SaucerPadding: "░",
				BarStart:      "│",
				BarEnd:        "│",
			}),
		)
		// Always write bar to stderr for visibility.
		bar = progressbar.NewOptions(len(payloads),
			progressbar.OptionSetDescription(fmt.Sprintf("[cyan][%-20s][reset]", tech.Name())),
			progressbar.OptionSetWriter(newStderrWriter()),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]█[reset]",
				SaucerHead:    "[green]▶[reset]",
				SaucerPadding: "░",
				BarStart:      "│",
				BarEnd:        "│",
			}),
		)

		threads := e.config.Threads
		if threads <= 0 {
			threads = 10
		}
		if threads > len(payloads) {
			threads = len(payloads)
		}

		payloadCh := make(chan Payload, len(payloads))
		for _, p := range payloads {
			payloadCh <- p
		}
		close(payloadCh)

		resultCh := make(chan Result, len(payloads))

		var wg sync.WaitGroup
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for p := range payloadCh {
					select {
					case <-ctx.Done():
						return
					default:
					}

					// Apply rate limiting.
					if e.config.RateLimiter != nil {
						if err := e.config.RateLimiter.Wait(ctx); err != nil {
							return
						}
					}

					var raw Result
					if p.UseCurl {
						raw = e.execCurl(ctx, p)
					} else {
						raw = e.executePayload(ctx, p)
					}

					resultCh <- raw
					_ = bar.Add(1)
				}
			}()
		}

		// Close result channel when all workers done.
		go func() {
			wg.Wait()
			close(resultCh)
		}()

		for sr := range resultCh {
			mu.Lock()
			allResults = append(allResults, sr)
			mu.Unlock()
		}

		_ = bar.Finish()
	}

	return allResults, nil
}

// executePayload sends a single bypass payload over HTTP and returns the raw Result.
func (e *Engine) executePayload(ctx context.Context, p Payload) Result {
	reqCtx, cancel := context.WithTimeout(ctx, e.config.Timeout)
	defer cancel()

	start := time.Now()

	var (
		req *http.Request
		err error
	)

	// Use Opaque URL approach for payloads with non-standard encoding.
	if p.RawURL != "" {
		req, err = buildRawURLRequest(reqCtx, p.Method, p.RawURL, p.Headers, p.Body)
	} else {
		req, err = buildRequest(reqCtx, p.Method, p.URL, p.Headers, p.Body)
	}
	if err != nil {
		return Result{
			Payload: p,
			Error:   fmt.Errorf("building request: %w", err),
		}
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return Result{
			Payload:      p,
			ResponseTime: time.Since(start).Milliseconds(),
			Error:        fmt.Errorf("executing request: %w", err),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1 MB
	if err != nil {
		return Result{
			Payload:      p,
			StatusCode:   resp.StatusCode,
			ResponseTime: time.Since(start).Milliseconds(),
			Error:        fmt.Errorf("reading body: %w", err),
		}
	}

	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])

	contentLength := resp.ContentLength
	if contentLength < 0 {
		contentLength = int64(len(body))
	}

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	return Result{
		Payload:       p,
		StatusCode:    resp.StatusCode,
		ContentLength: contentLength,
		BodyHash:      bodyHash,
		ContentType:   resp.Header.Get("Content-Type"),
		ResponseTime:  time.Since(start).Milliseconds(),
		Headers:       headers,
		Body:          body,
	}
}

// execCurl sends a payload via curl subprocess for HTTP version testing.
func (e *Engine) execCurl(ctx context.Context, p Payload) Result {
	reqCtx, cancel := context.WithTimeout(ctx, e.config.Timeout+5*time.Second)
	defer cancel()

	start := time.Now()

	args := []string{"-s", "-i"}

	if e.config.Insecure {
		args = append(args, "-k")
	}
	if e.config.ProxyURL != "" {
		args = append(args, "--proxy", e.config.ProxyURL)
	}
	if e.config.UserAgent != "" {
		args = append(args, "-A", e.config.UserAgent)
	}
	for k, v := range p.Headers {
		args = append(args, "-H", k+": "+v)
	}
	for _, arg := range p.CurlArgs {
		args = append(args, arg)
	}
	if p.Method != "" && p.Method != "GET" {
		args = append(args, "-X", p.Method)
	}

	target := p.URL
	if p.RawURL != "" {
		target = p.RawURL
	}
	args = append(args, target)

	cmd := exec.CommandContext(reqCtx, "curl", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		if reqCtx.Err() != nil {
			return Result{
				Payload:      p,
				ResponseTime: time.Since(start).Milliseconds(),
				Error:        fmt.Errorf("curl timeout: %w", reqCtx.Err()),
			}
		}
		// curl exits non-zero for HTTP errors too; check output.
		if out.Len() == 0 {
			return Result{
				Payload:      p,
				ResponseTime: time.Since(start).Milliseconds(),
				Error:        fmt.Errorf("curl failed: %w", err),
			}
		}
	}

	statusCode, contentLength, contentType, body := parseCurlOutput(out.Bytes())

	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])

	return Result{
		Payload:       p,
		StatusCode:    statusCode,
		ContentLength: contentLength,
		BodyHash:      bodyHash,
		ContentType:   contentType,
		ResponseTime:  time.Since(start).Milliseconds(),
		Body:          body,
	}
}

// parseCurlOutput parses curl -i output (headers + body) into components.
func parseCurlOutput(data []byte) (statusCode int, contentLength int64, contentType string, body []byte) {
	// Split header section from body on double CRLF.
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
	}
	if headerEnd == -1 {
		return 0, 0, "", data
	}

	headerSection := data[:headerEnd]
	body = data[headerEnd+4:]

	lines := bytes.Split(headerSection, []byte("\n"))
	for i, line := range lines {
		line = bytes.TrimRight(line, "\r")
		if i == 0 {
			// Status line: HTTP/1.1 200 OK
			parts := bytes.SplitN(line, []byte(" "), 3)
			if len(parts) >= 2 {
				sc, _ := strconv.Atoi(string(parts[1]))
				statusCode = sc
			}
			continue
		}
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx < 0 {
			continue
		}
		k := strings.ToLower(string(bytes.TrimSpace(line[:colonIdx])))
		v := string(bytes.TrimSpace(line[colonIdx+1:]))
		switch k {
		case "content-length":
			cl, _ := strconv.ParseInt(v, 10, 64)
			contentLength = cl
		case "content-type":
			contentType = v
		}
	}

	if contentLength == 0 {
		contentLength = int64(len(body))
	}
	return
}

// buildRequest creates a standard *http.Request.
func buildRequest(ctx context.Context, method, rawURL string, headers map[string]string, body string) (*http.Request, error) {
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// buildRawURLRequest creates an *http.Request using raw URL encoding via Opaque.
// This lets us send paths with %u002f, double-%25-encoded chars, etc. that
// net/url.Parse would otherwise reject or normalize.
func buildRawURLRequest(ctx context.Context, method, rawURL string, headers map[string]string, body string) (*http.Request, error) {
	if method == "" {
		method = "GET"
	}

	// Manually split off scheme + host so we can set Opaque to the raw path.
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 {
		return buildRequest(ctx, method, rawURL, headers, body)
	}
	scheme := rawURL[:schemeEnd]
	rest := rawURL[schemeEnd+3:]

	// Separate host from path.
	slashIdx := strings.IndexByte(rest, '/')
	if slashIdx < 0 {
		// No path — fall through to normal parse.
		return buildRequest(ctx, method, rawURL, headers, body)
	}
	host := rest[:slashIdx]
	rawPath := rest[slashIdx:]

	u := &url.URL{
		Scheme: scheme,
		Host:   host,
		Opaque: "//" + host + rawPath, // Opaque preserves raw encoding
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		// Fallback to normal request on parse failure.
		return buildRequest(ctx, method, rawURL, headers, body)
	}
	req.Host = host

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// stderrWriter is an io.Writer that writes to os.Stderr.
type stderrWriter struct{}

func newStderrWriter() io.Writer {
	return &stderrWriter{}
}

func (w *stderrWriter) Write(p []byte) (int, error) {
	return fmt.Fprint(io.Discard, string(p)) // suppress bar — handled by progressbar itself
}
