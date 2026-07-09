package bypass

import (
	"fmt"
	"strings"
	"unicode"
)

// PathCaseTechnique generates case-mutated variants of each path segment
// to bypass case-sensitive path matching rules.
type PathCaseTechnique struct{}

// Name returns the technique identifier.
func (t *PathCaseTechnique) Name() string { return "path-case" }

// Description returns a human-readable summary.
func (t *PathCaseTechnique) Description() string {
	return "Mutate path segment casing (UPPER, Title, aLtErNaTiNg) to bypass case-sensitive rules"
}

// caseVariants generates up to max distinct case variants of s.
// It always includes: UPPER, Title, and alternating case (aLtErNaTiNg).
// If the string has more than one character, it also generates
// alternating starting with uppercase (AlTeRnAtInG).
// Duplicates and the original are excluded.
func caseVariants(s string, max int) []string {
	if len(s) == 0 || max <= 0 {
		return nil
	}

	seen := make(map[string]struct{})
	seen[s] = struct{}{} // exclude original
	var variants []string

	add := func(v string) bool {
		if len(variants) >= max {
			return false
		}
		if _, exists := seen[v]; exists {
			return true // skip but continue
		}
		seen[v] = struct{}{}
		variants = append(variants, v)
		return len(variants) < max
	}

	// UPPER case
	if !add(strings.ToUpper(s)) {
		return variants
	}

	// Title case (first letter upper, rest lower)
	runes := []rune(s)
	titled := make([]rune, len(runes))
	for i, r := range runes {
		if i == 0 {
			titled[i] = unicode.ToUpper(r)
		} else {
			titled[i] = unicode.ToLower(r)
		}
	}
	if !add(string(titled)) {
		return variants
	}

	// aLtErNaTiNg (starts lower)
	alt := make([]rune, len(runes))
	for i, r := range runes {
		if i%2 == 0 {
			alt[i] = unicode.ToLower(r)
		} else {
			alt[i] = unicode.ToUpper(r)
		}
	}
	if !add(string(alt)) {
		return variants
	}

	// AlTeRnAtInG (starts upper)
	alt2 := make([]rune, len(runes))
	for i, r := range runes {
		if i%2 == 0 {
			alt2[i] = unicode.ToUpper(r)
		} else {
			alt2[i] = unicode.ToLower(r)
		}
	}
	if !add(string(alt2)) {
		return variants
	}

	// All lower (in case original isn't lowercase)
	if !add(strings.ToLower(s)) {
		return variants
	}

	// Generate more variants by flipping one character at a time.
	for i, r := range runes {
		if len(variants) >= max {
			break
		}
		toggled := make([]rune, len(runes))
		copy(toggled, runes)
		if unicode.IsUpper(r) {
			toggled[i] = unicode.ToLower(r)
		} else {
			toggled[i] = unicode.ToUpper(r)
		}
		add(string(toggled))
	}

	return variants
}

// Generate produces path-case payloads for the given target.
func (t *PathCaseTechnique) Generate(target *Target) []Payload {
	segs := target.Segments
	if len(segs) == 0 {
		return nil
	}

	const maxPerSegment = 16
	base := target.BaseURL()
	var payloads []Payload

	// For each segment, generate case variants and create payloads
	// with that segment replaced.
	for i, seg := range segs {
		// Skip segments that have no alphabetic characters.
		hasAlpha := false
		for _, r := range seg {
			if unicode.IsLetter(r) {
				hasAlpha = true
				break
			}
		}
		if !hasAlpha {
			continue
		}

		variants := caseVariants(seg, maxPerSegment)
		for _, v := range variants {
			mutated := replaceSeg(segs, i, v)
			path := joinPath(mutated...)
			fullURL := base + path
			desc := fmt.Sprintf("path-case: segment %d %q → %q", i, seg, v)
			payloads = append(payloads, makePayload(
				t.Name(), desc, "GET", fullURL, nil,
			))
		}
	}

	return payloads
}
