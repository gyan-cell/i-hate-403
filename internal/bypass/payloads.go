// Package bypass defines the technique interface, payload types, and bypass engine
// for the i-hate-403 tool.
package bypass

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// makePayload constructs a Payload with a properly parsed URL.
// The URL is parsed and reconstructed to normalize encoding.
func makePayload(technique, desc, method, rawURL string, headers map[string]string) Payload {
	p := Payload{
		TechniqueName: technique,
		Description:   desc,
		Method:        method,
		URL:           rawURL,
		Headers:       headers,
	}
	// Attempt to parse; if it fails the raw URL is still usable.
	if u, err := url.Parse(rawURL); err == nil {
		p.URL = u.String()
	}
	return p
}

// makeRawPayload constructs a Payload that preserves a raw URL string
// exactly as provided (for payloads containing encodings that net/url
// would mangle or reject).
func makeRawPayload(technique, desc, method, rawURL string, headers map[string]string) Payload {
	return Payload{
		TechniqueName: technique,
		Description:   desc,
		Method:        method,
		URL:           rawURL,
		RawURL:        rawURL,
		Headers:       headers,
	}
}

// joinPath joins path segments with '/' and ensures a leading '/'.
// Empty segments are preserved to allow double-slash injection.
func joinPath(segments ...string) string {
	path := "/" + strings.Join(segments, "/")
	return path
}

// replaceSeg returns a copy of segments with the element at idx replaced
// by replacement. The original slice is not modified.
func replaceSeg(segments []string, idx int, replacement string) []string {
	out := make([]string, len(segments))
	copy(out, segments)
	if idx >= 0 && idx < len(out) {
		out[idx] = replacement
	}
	return out
}

// insertSeg returns a copy of segments with insertion added before the
// element at idx. The original slice is not modified.
func insertSeg(segments []string, idx int, insertion string) []string {
	out := make([]string, 0, len(segments)+1)
	for i, s := range segments {
		if i == idx {
			out = append(out, insertion)
		}
		out = append(out, s)
	}
	// If idx == len(segments), insert at the end.
	if idx >= len(segments) {
		out = append(out, insertion)
	}
	return out
}

// percentEncode encodes every byte of s as %XX (uppercase hex).
func percentEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// doublePercentEncode applies percent encoding twice: each byte is first
// encoded as %XX, then the '%' in each %XX triplet is itself encoded as %25.
func doublePercentEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for i := 0; i < len(s); i++ {
		// First encode: %XX → then encode the '%' → %25XX
		fmt.Fprintf(&b, "%%25%02X", s[i])
	}
	return b.String()
}

// runePercentEncode encodes a single rune by percent-encoding each of its
// UTF-8 bytes as %XX.
func runePercentEncode(r rune) string {
	buf := make([]byte, utf8.UTFMax)
	n := utf8.EncodeRune(buf, r)
	var b strings.Builder
	b.Grow(n * 3)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%%%02X", buf[i])
	}
	return b.String()
}
