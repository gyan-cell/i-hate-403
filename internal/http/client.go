// Package httpclient provides a configurable HTTP client with rate limiting,
// custom transport settings, proxy support, and raw URL request capabilities.
package httpclient

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Config holds configuration for the HTTP client.
type Config struct {
	// Timeout is the overall request timeout.
	Timeout time.Duration
	// ProxyURL is the URL of the HTTP/SOCKS proxy to use. Empty means no proxy.
	ProxyURL string
	// Insecure disables TLS certificate verification when true.
	Insecure bool
	// UserAgent is the User-Agent header sent with every request.
	UserAgent string
	// MaxRedirects controls redirect following. Currently unused because the
	// client is configured to never follow redirects.
	MaxRedirects int
	// RateLimiter optionally throttles outgoing requests. Nil means no limit.
	RateLimiter *rate.Limiter
}

// Client wraps an *http.Client with project-specific configuration.
type Client struct {
	httpClient *http.Client
	cfg        Config
}

// NewClient creates a new Client using the provided Config.
// The underlying http.Client uses a custom Transport and never follows redirects.
func NewClient(cfg Config) *Client {
	transport := NewTransport(cfg)

	hc := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		// Never follow redirects; let the caller handle them.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{
		httpClient: hc,
		cfg:        cfg,
	}
}

// Do executes an HTTP request with the configured User-Agent and optional rate
// limiting. It respects the provided context for cancellation and deadlines.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Apply rate limiting if configured.
	if c.cfg.RateLimiter != nil {
		if err := c.cfg.RateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}
	}

	// Set User-Agent if configured and not already set on the request.
	if c.cfg.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}

	// Attach context to the request.
	req = req.WithContext(ctx)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}

	return resp, nil
}

// DoRaw sends a request using a raw (potentially non-standard) URL string.
// This is useful for bypass techniques that rely on malformed or unusual paths.
func (c *Client) DoRaw(ctx context.Context, method, rawURL string, headers map[string]string, body string) (*http.Response, error) {
	req, err := NewRawRequest(ctx, method, rawURL, headers, body)
	if err != nil {
		return nil, fmt.Errorf("creating raw request: %w", err)
	}

	// Apply rate limiting if configured.
	if c.cfg.RateLimiter != nil {
		if err := c.cfg.RateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait: %w", err)
		}
	}

	// Set User-Agent if configured and not already set.
	if c.cfg.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("raw http request failed: %w", err)
	}

	return resp, nil
}

// HTTPClient returns the underlying *http.Client for use with external
// libraries that require a standard http.Client.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// bodyReader returns an io.Reader for the given body string, or nil if empty.
func bodyReader(body string) *strings.Reader {
	if body == "" {
		return nil
	}
	return strings.NewReader(body)
}
