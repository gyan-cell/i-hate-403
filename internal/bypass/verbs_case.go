// Package bypass — case-permutation verb bypass technique.
package bypass

import "strings"

// VerbsCaseTechnique tests case-permutation variants of common HTTP verbs.
type VerbsCaseTechnique struct{}

func (v *VerbsCaseTechnique) Name() string        { return "verbs-case" }
func (v *VerbsCaseTechnique) Description() string { return "HTTP method case permutations" }

// Generate produces up to 8 case-permuted variants per method.
func (v *VerbsCaseTechnique) Generate(target *Target) []Payload {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}

	needsCL := map[string]bool{"POST": true, "PUT": true, "PATCH": true}

	var payloads []Payload
	for _, m := range methods {
		perms := casePermutations(m, 8)
		for _, perm := range perms {
			// Skip the original uppercase form; VerbsTechnique handles it.
			if perm == m {
				continue
			}
			p := Payload{
				TechniqueName: v.Name(),
				Description:   "CaseVerb " + perm,
				Method:        perm,
				URL:           target.FullURL(),
				Headers:       make(map[string]string),
			}
			if needsCL[m] {
				p.Headers["Content-Length"] = "0"
			}
			payloads = append(payloads, p)
		}
	}
	return payloads
}

// casePermutations generates up to max unique case variations of s.
func casePermutations(s string, max int) []string {
	if len(s) == 0 {
		return []string{""}
	}
	n := len(s)
	total := 1 << n
	if total > max {
		total = max
	}

	seen := make(map[string]bool)
	var results []string
	for mask := 0; len(results) < total; mask++ {
		if mask >= (1 << n) {
			break
		}
		var b strings.Builder
		b.Grow(n)
		for i := 0; i < n; i++ {
			c := s[i]
			if mask&(1<<i) != 0 {
				if c >= 'A' && c <= 'Z' {
					c = c + 32
				} else if c >= 'a' && c <= 'z' {
					c = c - 32
				}
			}
			b.WriteByte(c)
		}
		out := b.String()
		if !seen[out] {
			seen[out] = true
			results = append(results, out)
		}
	}
	return results
}
