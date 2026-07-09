package bypass

import (
	"fmt"
	"testing"
)

// TestOverlongTwoByte verifies the 2-byte overlong UTF-8 encoding of ASCII chars.
// The formula is: byte1 = 0xC0 | (c>>6), byte2 = 0x80 | (c&0x3F)
func TestOverlongTwoByte(t *testing.T) {
	tests := []struct {
		name  string
		input byte
		want  [2]byte
	}{
		// '/' = 0x2F = 0b00101111
		// byte1: 0xC0 | (0x2F>>6) = 0xC0 | 0x00 = 0xC0
		// byte2: 0x80 | (0x2F&0x3F) = 0x80 | 0x2F = 0xAF
		{name: "slash 0x2F", input: 0x2F, want: [2]byte{0xC0, 0xAF}},

		// '.' = 0x2E = 0b00101110
		// byte1: 0xC0 | (0x2E>>6) = 0xC0 | 0x00 = 0xC0
		// byte2: 0x80 | (0x2E&0x3F) = 0x80 | 0x2E = 0xAE
		{name: "dot 0x2E", input: 0x2E, want: [2]byte{0xC0, 0xAE}},

		// 'a' = 0x61 = 0b01100001
		// byte1: 0xC0 | (0x61>>6) = 0xC0 | 0x01 = 0xC1
		// byte2: 0x80 | (0x61&0x3F) = 0x80 | 0x21 = 0xA1
		{name: "letter a 0x61", input: 0x61, want: [2]byte{0xC1, 0xA1}},

		// NUL = 0x00
		// byte1: 0xC0 | 0 = 0xC0, byte2: 0x80 | 0 = 0x80
		{name: "nul 0x00", input: 0x00, want: [2]byte{0xC0, 0x80}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := overlongTwoByte(tc.input)
			if got != tc.want {
				t.Errorf("overlongTwoByte(0x%02X) = [0x%02X, 0x%02X], want [0x%02X, 0x%02X]",
					tc.input, got[0], got[1], tc.want[0], tc.want[1])
			}
		})
	}
}

// TestOverlongThreeByte verifies the 3-byte overlong UTF-8 encoding of ASCII chars.
func TestOverlongThreeByte(t *testing.T) {
	tests := []struct {
		name  string
		input byte
		want  [3]byte
	}{
		// '/' = 0x2F, u16 = 0x002F
		// byte1: 0xE0 | (0x002F>>12) = 0xE0 | 0 = 0xE0
		// byte2: 0x80 | ((0x002F>>6)&0x3F) = 0x80 | 0x00 = 0x80
		// byte3: 0x80 | (0x002F&0x3F) = 0x80 | 0x2F = 0xAF
		{name: "slash 0x2F", input: 0x2F, want: [3]byte{0xE0, 0x80, 0xAF}},

		// '.' = 0x2E
		// byte1: 0xE0, byte2: 0x80, byte3: 0x80|0x2E = 0xAE
		{name: "dot 0x2E", input: 0x2E, want: [3]byte{0xE0, 0x80, 0xAE}},

		// 'a' = 0x61, u16 = 0x0061
		// byte1: 0xE0 | (0x0061>>12) = 0xE0 | 0 = 0xE0
		// byte2: 0x80 | ((0x0061>>6)&0x3F) = 0x80 | 0x01 = 0x81
		// byte3: 0x80 | (0x0061&0x3F) = 0x80 | 0x21 = 0xA1
		{name: "letter a 0x61", input: 0x61, want: [3]byte{0xE0, 0x81, 0xA1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := overlongThreeByte(tc.input)
			if got != tc.want {
				t.Errorf("overlongThreeByte(0x%02X) = [0x%02X, 0x%02X, 0x%02X], want [0x%02X, 0x%02X, 0x%02X]",
					tc.input, got[0], got[1], got[2], tc.want[0], tc.want[1], tc.want[2])
			}
		})
	}
}

// TestIISUnicodeEscape verifies %uXXXX encoding for ASCII chars.
func TestIISUnicodeEscape(t *testing.T) {
	tests := []struct {
		input byte
		want  string
	}{
		{input: 0x2F, want: "%u002F"},
		{input: 0x2E, want: "%u002E"},
		{input: 0x61, want: "%u0061"},
		{input: 0x00, want: "%u0000"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("0x%02X", tc.input), func(t *testing.T) {
			got := iisUnicodeEscape(tc.input)
			if got != tc.want {
				t.Errorf("iisUnicodeEscape(0x%02X) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestUnicodeTechniqueGeneratesPayloads verifies that UnicodeTechnique produces
// at least one payload for a normal target.
func TestUnicodeTechniqueGeneratesPayloads(t *testing.T) {
	target := &Target{
		Scheme:   "https",
		Host:     "example.com",
		Path:     "/admin",
		Segments: []string{"admin"},
	}
	tech := &UnicodeTechnique{}
	payloads := tech.Generate(target)
	if len(payloads) == 0 {
		t.Error("UnicodeTechnique.Generate returned no payloads")
	}
	for _, p := range payloads {
		if p.TechniqueName != "unicode" {
			t.Errorf("expected TechniqueName=unicode, got %q", p.TechniqueName)
		}
		if p.Method == "" {
			t.Error("payload has empty Method")
		}
		if p.URL == "" && p.RawURL == "" {
			t.Error("payload has neither URL nor RawURL")
		}
	}
}
