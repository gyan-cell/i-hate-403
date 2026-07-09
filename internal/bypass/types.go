// Package bypass defines the technique interface, payload types, and bypass engine
// for the i-hate-403 tool.
package bypass

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// Technique is the interface every bypass module must implement.
// Each technique generates a list of Payloads to test against a Target.
type Technique interface {
	// Name returns the short CLI name (e.g. "headers", "midpaths").
	Name() string
	// Description returns a human-readable summary of the technique.
	Description() string
	// Generate produces all bypass payloads for the given target.
	Generate(target *Target) []Payload
}

// Target holds the parsed target information that techniques use to generate payloads.
type Target struct {
	// OriginalURL is the full URL as provided by the user.
	OriginalURL string
	// Scheme is the URL scheme (http or https).
	Scheme string
	// Host is the host:port portion of the URL.
	Host string
	// Path is the decoded URL path (e.g. "/admin/panel").
	Path string
	// RawPath is the raw URL path preserving encoding (may be empty if no encoding).
	RawPath string
	// Segments are the individual path components split on '/'.
	Segments []string
	// RawQuery is the query string without '?'.
	RawQuery string
	// Fragment is the URL fragment without '#'.
	Fragment string
	// BypassIPs is the list of IPs to use in header-based bypasses.
	BypassIPs []string
	// Marker is the custom payload position marker (e.g. "§").
	Marker string
	// RawRequest is a parsed raw HTTP request file (Burp/ZAP format).
	RawRequest *RawHTTPRequest
	// UserAgent is the User-Agent to use in requests.
	UserAgent string
}

// DefaultBypassIPs are the default IPs used for header-based bypass techniques.
var DefaultBypassIPs = []string{
	"127.0.0.1",
	"0.0.0.0",
	"::1",
	"10.0.0.1",
	"169.254.169.254",
	"127.0.0.1:80",
	"127.0.0.1:443",
	"localhost",
	"2130706433",       // 127.0.0.1 as decimal
	"0x7f000001",       // 127.0.0.1 as hex
	"0177.0.0.1",       // 127.0.0.1 as octal
	"::ffff:127.0.0.1", // IPv4-mapped IPv6
}

// ParseTarget parses a URL string into a Target with the given options.
func ParseTarget(rawURL string, bypassIPs []string, marker, userAgent string) (*Target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL %q: %w", rawURL, err)
	}

	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL %q has no host", rawURL)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	ips := bypassIPs
	if len(ips) == 0 {
		ips = DefaultBypassIPs
	}

	segments := splitPath(path)

	return &Target{
		OriginalURL: rawURL,
		Scheme:      u.Scheme,
		Host:        u.Host,
		Path:        path,
		RawPath:     u.RawPath,
		Segments:    segments,
		RawQuery:    u.RawQuery,
		Fragment:    u.Fragment,
		BypassIPs:   ips,
		Marker:      marker,
		UserAgent:   userAgent,
	}, nil
}

// BaseURL returns the scheme://host portion of the target.
func (t *Target) BaseURL() string {
	return t.Scheme + "://" + t.Host
}

// FullURL reconstructs the full URL from target components.
func (t *Target) FullURL() string {
	u := t.BaseURL() + t.Path
	if t.RawQuery != "" {
		u += "?" + t.RawQuery
	}
	return u
}

// splitPath splits a URL path into non-empty segments.
func splitPath(path string) []string {
	var segments []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	return segments
}

// Payload represents a single bypass request to send.
type Payload struct {
	// TechniqueName is the name of the technique that generated this payload.
	TechniqueName string
	// Description is a human-readable label for this specific payload.
	Description string
	// Method is the HTTP method to use.
	Method string
	// URL is the full URL to request (may contain non-standard encoding).
	URL string
	// RawURL is used when the URL contains encodings that net/url rejects.
	// When set, the HTTP client should use this raw string in the request line.
	RawURL string
	// Headers are extra headers to set on the request.
	Headers map[string]string
	// Body is the request body (usually empty for bypass tests).
	Body string
	// UseCurl indicates this payload must be sent via curl subprocess
	// (used for HTTP version testing).
	UseCurl bool
	// CurlArgs are extra curl arguments (e.g. --http1.0, --http2).
	CurlArgs []string
	// HTTPVersion overrides the HTTP version string (e.g. "HTTP/1.0").
	HTTPVersion string
}

// RawHTTPRequest represents a parsed Burp/ZAP raw HTTP request.
type RawHTTPRequest struct {
	// Method is the HTTP method from the request line.
	Method string
	// Path is the request path from the request line.
	Path string
	// HTTPVersion is the HTTP version from the request line (e.g. "HTTP/1.1").
	HTTPVersion string
	// Headers preserves original header order and casing.
	Headers []RawHeader
	// Body is the raw request body.
	Body string
	// Host is extracted from the Host header.
	Host string
	// Scheme is inferred (https if port 443, else http).
	Scheme string
}

// RawHeader is a key-value header pair preserving original casing.
type RawHeader struct {
	Key   string
	Value string
}

// Result is the raw response data from executing a single payload.
type Result struct {
	Payload       Payload
	StatusCode    int
	ContentLength int64
	BodyHash      string // SHA-256 hex
	ContentType   string
	ResponseTime  int64 // milliseconds
	Headers       map[string]string
	Body          []byte
	Error         error
}

// Registry holds all registered techniques keyed by name.
type Registry struct {
	mu         sync.RWMutex
	techniques map[string]Technique
	order      []string // insertion order
}

// NewRegistry creates a new technique registry.
func NewRegistry() *Registry {
	return &Registry{
		techniques: make(map[string]Technique),
	}
}

// Register adds a technique to the registry.
func (r *Registry) Register(t Technique) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := t.Name()
	if _, exists := r.techniques[name]; !exists {
		r.order = append(r.order, name)
	}
	r.techniques[name] = t
}

// Get retrieves a technique by name.
func (r *Registry) Get(name string) (Technique, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.techniques[name]
	return t, ok
}

// All returns all registered techniques in insertion order.
func (r *Registry) All() []Technique {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Technique, 0, len(r.order))
	for _, name := range r.order {
		result = append(result, r.techniques[name])
	}
	return result
}

// Filter returns techniques matching the given comma-separated names.
// If filter is empty or "all", returns all techniques.
func (r *Registry) Filter(filter string) []Technique {
	if filter == "" || strings.ToLower(filter) == "all" {
		return r.All()
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := strings.Split(filter, ",")
	var result []Technique
	for _, name := range names {
		name = strings.TrimSpace(name)
		if t, ok := r.techniques[name]; ok {
			result = append(result, t)
		}
	}
	return result
}

// Names returns all registered technique names in order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// DefaultRegistry creates a registry with all built-in techniques.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(&VerbsTechnique{})
	r.Register(&VerbsCaseTechnique{})
	r.Register(&HeadersTechnique{})
	r.Register(&EndpathsTechnique{})
	r.Register(&MidpathsTechnique{})
	r.Register(&DoubleEncodingTechnique{})
	r.Register(&UnicodeTechnique{})
	r.Register(&PathCaseTechnique{})
	r.Register(&HTTPVersionsTechnique{})
	r.Register(&CustomPositionTechnique{})
	r.Register(&RawRequestTechnique{})
	return r
}

// QuickTechniques are the technique names used in --quick mode.
var QuickTechniques = []string{"headers", "midpaths", "endpaths", "verbs"}
