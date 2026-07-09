// Package bypass — HTTP version bypass technique.
package bypass

// HTTPVersionsTechnique tests different HTTP protocol versions via curl.
type HTTPVersionsTechnique struct{}

func (h *HTTPVersionsTechnique) Name() string        { return "http-versions" }
func (h *HTTPVersionsTechnique) Description() string { return "HTTP protocol version testing" }

// Generate produces curl-based payloads for HTTP/1.0, HTTP/1.1, and HTTP/2.
func (h *HTTPVersionsTechnique) Generate(target *Target) []Payload {
	versions := []struct {
		flag    string
		version string
	}{
		{"--http1.0", "HTTP/1.0"},
		{"--http1.1", "HTTP/1.1"},
		{"--http2", "HTTP/2"},
	}

	payloads := make([]Payload, 0, len(versions))
	for _, v := range versions {
		payloads = append(payloads, Payload{
			TechniqueName: h.Name(),
			Description:   v.version,
			Method:        "GET",
			URL:           target.FullURL(),
			Headers:       make(map[string]string),
			UseCurl:       true,
			CurlArgs:      []string{v.flag},
			HTTPVersion:   v.version,
		})
	}
	return payloads
}
