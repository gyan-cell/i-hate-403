// Package calibrate provides baseline capture, auto-calibration with tolerance
// bands, fragment-based calibration, and frontend/WAF fingerprinting.
package calibrate

import (
	"net/http"
)

// Baseline holds the captured response signature of the original blocked request.
type Baseline struct {
	// StatusCode is the HTTP status code of the blocked request.
	StatusCode int
	// ContentLength is the response body size in bytes.
	ContentLength int64
	// BodyHash is the SHA-256 hex digest of the response body.
	BodyHash string
	// ContentType is the Content-Type header value.
	ContentType string
	// Headers are all response headers from the blocked request.
	Headers http.Header
	// Tolerance is the dynamic tolerance band computed from calibration requests.
	Tolerance ToleranceBand
	// FragmentStripped is true if the server/proxy strips URL fragments.
	FragmentStripped bool
	// Fingerprint identifies the frontend server/CDN/WAF.
	Fingerprint *Fingerprint
}

// ToleranceBand defines the acceptable variation in content-length for the target.
// Responses within this band are considered "normal" (not a bypass).
type ToleranceBand struct {
	// Mean is the average content-length of calibration responses.
	Mean float64
	// StdDev is the standard deviation of calibration response lengths.
	StdDev float64
	// Min is the lower bound of the tolerance band (Mean - 2*StdDev).
	Min float64
	// Max is the upper bound of the tolerance band (Mean + 2*StdDev).
	Max float64
	// Samples is the number of calibration requests used to compute the band.
	Samples int
	// SoftNotFound is true if the server returns 200 for non-existent paths
	// (custom 404 pages that return 200 status).
	SoftNotFound bool
}

// Fingerprint identifies the frontend server, CDN, or WAF.
type Fingerprint struct {
	// Server is the value of the Server header.
	Server string
	// Via is the value of the Via header (proxy chain info).
	Via string
	// PoweredBy is the value of the X-Powered-By header.
	PoweredBy string
	// CDN is the identified CDN (e.g. "Cloudflare", "Akamai", "CloudFront").
	CDN string
	// WebServer is the identified web server (e.g. "nginx", "Apache", "IIS").
	WebServer string
	// WAF is the identified WAF (e.g. "Cloudflare", "AWS WAF", "ModSecurity").
	WAF string
	// Technology is any additional technology identified from headers or body patterns.
	Technology string
	// Raw is the raw header map used for fingerprinting.
	Raw http.Header
}

// String returns a human-readable fingerprint summary.
func (f *Fingerprint) String() string {
	if f == nil {
		return "unknown"
	}
	parts := []string{}
	if f.WebServer != "" {
		parts = append(parts, f.WebServer)
	}
	if f.CDN != "" {
		parts = append(parts, f.CDN)
	}
	if f.WAF != "" {
		parts = append(parts, "WAF:"+f.WAF)
	}
	if f.Technology != "" {
		parts = append(parts, f.Technology)
	}
	if len(parts) == 0 {
		if f.Server != "" {
			return f.Server
		}
		return "unknown"
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " | "
		}
		result += p
	}
	return result
}
