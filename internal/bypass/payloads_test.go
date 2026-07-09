package bypass

import (
	"strings"
	"testing"
)

// TestParseTargetBasic verifies URL parsing into Target fields.
func TestParseTargetBasic(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantScheme  string
		wantHost    string
		wantPath    string
		wantSegs    []string
		wantErrFrag string // if non-empty, expect error containing this
	}{
		{
			name:       "full https URL with path",
			url:        "https://example.com/admin/panel",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/admin/panel",
			wantSegs:   []string{"admin", "panel"},
		},
		{
			name:       "http URL with port",
			url:        "http://example.com:8080/api/v1",
			wantScheme: "http",
			wantHost:   "example.com:8080",
			wantPath:   "/api/v1",
			wantSegs:   []string{"api", "v1"},
		},
		{
			name:       "URL with no path",
			url:        "https://example.com",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/",
			wantSegs:   nil,
		},
		{
			name:        "no host",
			url:         "https://",
			wantErrFrag: "no host",
		},
		{
			name:       "URL with query string",
			url:        "https://example.com/admin?foo=bar",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/admin",
			wantSegs:   []string{"admin"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTarget(tc.url, nil, "§", "test-agent")
			if tc.wantErrFrag != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrFrag)
				}
				if !strings.Contains(err.Error(), tc.wantErrFrag) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrFrag)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Scheme != tc.wantScheme {
				t.Errorf("Scheme = %q, want %q", got.Scheme, tc.wantScheme)
			}
			if got.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tc.wantHost)
			}
			if got.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tc.wantPath)
			}
			if len(got.Segments) != len(tc.wantSegs) {
				t.Errorf("Segments = %v, want %v", got.Segments, tc.wantSegs)
			}
		})
	}
}

// TestJoinPath verifies the joinPath utility joins segments correctly.
func TestJoinPath(t *testing.T) {
	tests := []struct {
		segs []string
		want string
	}{
		{segs: []string{"admin"}, want: "/admin"},
		{segs: []string{"admin", "panel"}, want: "/admin/panel"},
		{segs: []string{}, want: "/"},
		{segs: []string{"", "admin"}, want: "//admin"}, // preserves explicit empty segs
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := joinPath(tc.segs...)
			if got != tc.want {
				t.Errorf("joinPath(%v) = %q, want %q", tc.segs, got, tc.want)
			}
		})
	}
}

// TestEndpathsTechniqueGenerate verifies that endpaths generates expected suffixes.
func TestEndpathsTechniqueGenerate(t *testing.T) {
	target := &Target{
		Scheme:   "https",
		Host:     "example.com",
		Path:     "/admin",
		Segments: []string{"admin"},
	}
	tech := &EndpathsTechnique{}
	payloads := tech.Generate(target)
	if len(payloads) == 0 {
		t.Fatal("expected payloads, got none")
	}
	// Check that trailing slash variant exists.
	var hasTrailingSlash bool
	for _, p := range payloads {
		if strings.HasSuffix(p.URL, "/admin/") || strings.HasSuffix(p.RawURL, "/admin/") {
			hasTrailingSlash = true
		}
		if p.TechniqueName != "endpaths" {
			t.Errorf("expected TechniqueName=endpaths, got %q", p.TechniqueName)
		}
	}
	if !hasTrailingSlash {
		t.Error("expected a payload with trailing slash /admin/")
	}
}

// TestMidpathsTechniqueGenerate verifies midpaths generates injection payloads.
func TestMidpathsTechniqueGenerate(t *testing.T) {
	target := &Target{
		Scheme:   "https",
		Host:     "example.com",
		Path:     "/admin/panel",
		Segments: []string{"admin", "panel"},
	}
	tech := &MidpathsTechnique{}
	payloads := tech.Generate(target)
	if len(payloads) == 0 {
		t.Fatal("expected payloads, got none")
	}
	// Verify payloads have valid method and URL.
	for _, p := range payloads {
		if p.Method == "" {
			t.Error("payload has empty Method")
		}
		if p.TechniqueName != "midpaths" {
			t.Errorf("expected TechniqueName=midpaths, got %q", p.TechniqueName)
		}
	}
}

// TestCaseVariants verifies that caseVariants returns expected case permutations.
func TestCaseVariants(t *testing.T) {
	tests := []struct {
		input       string
		max         int
		wantContain []string // must be in result
		wantLen     int      // expected count (exact or >=)
	}{
		{
			input:       "admin",
			max:         16,
			wantContain: []string{"ADMIN", "Admin"},
			wantLen:     3, // at least upper, title, alternating
		},
		{
			input:   "a",
			max:     16,
			wantLen: 1, // just "A" for a single char
		},
		{
			input:   "",
			max:     16,
			wantLen: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := caseVariants(tc.input, tc.max)
			if len(got) < tc.wantLen {
				t.Errorf("caseVariants(%q, %d) returned %d variants, want >= %d: %v",
					tc.input, tc.max, len(got), tc.wantLen, got)
			}
			for _, want := range tc.wantContain {
				found := false
				for _, v := range got {
					if v == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("caseVariants(%q) missing expected variant %q; got: %v", tc.input, want, got)
				}
			}
			// Verify max is respected.
			if len(got) > tc.max {
				t.Errorf("caseVariants returned %d variants, exceeds max %d", len(got), tc.max)
			}
		})
	}
}
