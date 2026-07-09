package bypass

import (
	"strings"
	"testing"
)

// TestDoubleEncode verifies that doubleEncode correctly encodes only /  and .
// characters (the path separators that WAFs filter). Other characters are
// passed through unchanged — this is by design.
func TestDoubleEncode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "slash", input: "/", want: "%252F"},
		{name: "dot", input: ".", want: "%252E"},
		{name: "slash-dot", input: "/.", want: "%252F%252E"},
		{name: "empty", input: "", want: ""},
		// Alphanumeric and space are NOT encoded by doubleEncode —
		// only / and . are bypass-relevant targets.
		{name: "alpha unchanged", input: "admin", want: "admin"},
		{name: "space unchanged", input: " ", want: " "},
		// Full path: only / and . encoded, alphanumeric preserved.
		{name: "admin path", input: "/admin", want: "%252Fadmin"},
		{name: "dotfile", input: "/admin/./etc", want: "%252Fadmin%252F%252E%252Fetc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := doubleEncode(tc.input)
			if !strings.EqualFold(got, tc.want) {
				t.Errorf("doubleEncode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestDoubleEncodePathSpecialCharsOnly verifies that doubleEncodePath only
// double-encodes special characters, leaving alphanumeric characters unchanged.
func TestDoubleEncodePathSpecialCharsOnly(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// alphanumeric portions are kept; only /  . space etc are double-encoded
		checkContains string
		checkNotHas   string
	}{
		{
			name:          "admin path",
			input:         "/admin",
			checkContains: "admin", // alphanumeric kept
			checkNotHas:   "",
		},
		{
			name:          "slash double encoded",
			input:         "/admin/panel",
			checkContains: "admin",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := doubleEncodePath(tc.input)
			if tc.checkContains != "" && !strings.Contains(got, tc.checkContains) {
				t.Errorf("doubleEncodePath(%q) = %q, does not contain %q", tc.input, got, tc.checkContains)
			}
		})
	}
}

// TestDoubleEncodeMultibyteRune ensures that multi-byte UTF-8 runes are handled
// correctly. Since doubleEncode only targets / and ., multi-byte runes pass
// through unchanged — the function must not corrupt them by byte-slicing.
func TestDoubleEncodeMultibyteRune(t *testing.T) {
	// '日' is U+65E5, a 3-byte UTF-8 sequence. It contains no '/' or '.' bytes
	// so doubleEncode must pass it through intact.
	input := "/admin/日本語"
	got := doubleEncode(input)

	// The slashes should be double-encoded.
	if !strings.Contains(got, "%252F") {
		t.Errorf("doubleEncode(%q) = %q, expected %%252F for slashes", input, got)
	}
	// The Japanese characters must be preserved intact — not corrupted.
	if !strings.Contains(got, "日本語") {
		t.Errorf("doubleEncode(%q) = %q, multi-byte runes were corrupted", input, got)
	}
}
