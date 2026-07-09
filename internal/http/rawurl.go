package httpclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// NewRawRequest creates an *http.Request that preserves the raw URL path exactly
// as provided. This is critical for bypass techniques that rely on malformed,
// double-encoded, or otherwise non-standard URL paths that Go's net/http would
// normally normalize.
func NewRawRequest(ctx context.Context, method, rawURL string, headers map[string]string, body string) (*http.Request, error) {
	if method == "" {
		method = http.MethodGet
	}

	// Parse the URL manually to extract scheme, host, and raw path.
	scheme, host, rawPath, err := splitRawURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing raw URL %q: %w", rawURL, err)
	}

	// Build the request with an opaque URL to prevent path normalization.
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	var req *http.Request
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, rawURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Override the URL with an opaque form to preserve the raw path.
	// The Opaque field tells Go's HTTP client to use this value as-is in the
	// request line instead of encoding/normalizing req.URL.Path.
	req.URL = &url.URL{
		Scheme: scheme,
		Host:   host,
		Opaque: "//" + host + rawPath,
	}

	// Set the Host header explicitly.
	req.Host = host

	// Apply custom headers.
	for key, val := range headers {
		req.Header.Set(key, val)
	}

	return req, nil
}

// splitRawURL extracts scheme, host, and raw path from a URL string without
// performing any path normalization.
func splitRawURL(rawURL string) (scheme, host, rawPath string, err error) {
	if rawURL == "" {
		return "", "", "", fmt.Errorf("empty URL")
	}

	// Extract scheme.
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 {
		return "", "", "", fmt.Errorf("missing scheme in URL %q", rawURL)
	}
	scheme = rawURL[:schemeEnd]
	rest := rawURL[schemeEnd+3:]

	// Extract host (everything before the first '/').
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		// URL with no path, e.g. "https://example.com"
		host = rest
		rawPath = "/"
	} else {
		host = rest[:slashIdx]
		rawPath = rest[slashIdx:]
	}

	if host == "" {
		return "", "", "", fmt.Errorf("empty host in URL %q", rawURL)
	}

	return scheme, host, rawPath, nil
}
