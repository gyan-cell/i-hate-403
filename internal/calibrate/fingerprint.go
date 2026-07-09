package calibrate

import (
	"net/http"
	"strings"
)

// IdentifyFingerprint analyzes HTTP response headers and body content to
// identify the web server, CDN, and WAF in front of the target.
func IdentifyFingerprint(headers http.Header, body []byte) *Fingerprint {
	fp := &Fingerprint{
		Server:    headers.Get("Server"),
		Via:       headers.Get("Via"),
		PoweredBy: headers.Get("X-Powered-By"),
		Raw:       headers.Clone(),
	}

	// Identify web server from Server header.
	fp.WebServer = identifyWebServer(fp.Server, body)

	// Identify CDN from headers.
	fp.CDN = identifyCDN(headers)

	// Identify WAF from headers and body.
	fp.WAF = identifyWAF(headers, body)

	// Identify additional technology from X-Powered-By.
	fp.Technology = identifyTechnology(fp.PoweredBy, headers)

	return fp
}

// identifyWebServer detects the web server from the Server header value and
// response body patterns.
func identifyWebServer(server string, body []byte) string {
	serverLower := strings.ToLower(server)
	bodyLower := strings.ToLower(string(body))

	switch {
	case strings.Contains(serverLower, "nginx"):
		return "nginx"
	case strings.Contains(serverLower, "apache"):
		return "Apache"
	case strings.Contains(serverLower, "microsoft-iis"):
		return "IIS"
	case strings.Contains(serverLower, "litespeed"):
		return "LiteSpeed"
	case strings.Contains(serverLower, "caddy"):
		return "Caddy"
	case strings.Contains(serverLower, "openresty"):
		return "OpenResty"
	}

	// Fall back to body pattern matching for error pages.
	switch {
	case strings.Contains(bodyLower, "nginx"):
		return "nginx"
	case strings.Contains(bodyLower, "apache") && strings.Contains(bodyLower, "server at"):
		return "Apache"
	case strings.Contains(bodyLower, "microsoft-iis") || strings.Contains(bodyLower, "iis"):
		return "IIS"
	}

	return ""
}

// identifyCDN detects the CDN provider from response headers.
func identifyCDN(headers http.Header) string {
	// Cloudflare: cf-ray header is definitive.
	if headers.Get("cf-ray") != "" {
		return "Cloudflare"
	}

	// CloudFront: x-amz-cf-id or x-amz-cf-pop headers.
	if headers.Get("x-amz-cf-id") != "" || headers.Get("x-amz-cf-pop") != "" {
		return "CloudFront"
	}

	// Akamai: various Akamai-specific headers.
	if headers.Get("X-Akamai-Transformed") != "" ||
		headers.Get("X-Akamai-Request-ID") != "" {
		return "Akamai"
	}

	// Fastly: x-served-by often contains "cache-" for Fastly.
	if servedBy := headers.Get("x-served-by"); servedBy != "" {
		if strings.Contains(strings.ToLower(servedBy), "cache-") {
			return "Fastly"
		}
	}

	// Varnish: Via or X-Varnish headers.
	if headers.Get("X-Varnish") != "" {
		return "Varnish"
	}
	if via := headers.Get("Via"); strings.Contains(strings.ToLower(via), "varnish") {
		return "Varnish"
	}

	// Check Server header for CDN hints.
	serverLower := strings.ToLower(headers.Get("Server"))
	switch {
	case strings.Contains(serverLower, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(serverLower, "cloudfront"):
		return "CloudFront"
	case strings.Contains(serverLower, "akamaighost"):
		return "Akamai"
	}

	return ""
}

// identifyWAF detects web application firewalls from response headers and body.
func identifyWAF(headers http.Header, body []byte) string {
	bodyLower := strings.ToLower(string(body))

	// Cloudflare WAF (when acting as WAF, not just CDN).
	if headers.Get("cf-ray") != "" && headers.Get("cf-mitigated") != "" {
		return "Cloudflare"
	}

	// AWS WAF.
	if headers.Get("x-amzn-waf-action") != "" {
		return "AWS WAF"
	}

	// ModSecurity.
	if server := strings.ToLower(headers.Get("Server")); strings.Contains(server, "mod_security") ||
		strings.Contains(server, "modsecurity") {
		return "ModSecurity"
	}
	if strings.Contains(bodyLower, "modsecurity") ||
		strings.Contains(bodyLower, "mod_security") {
		return "ModSecurity"
	}

	// Imperva / Incapsula.
	if headers.Get("X-CDN") == "Incapsula" || headers.Get("X-Iinfo") != "" {
		return "Imperva"
	}

	// F5 BIG-IP ASM.
	if strings.Contains(bodyLower, "the requested url was rejected") ||
		headers.Get("X-WA-Info") != "" {
		return "F5 BIG-IP"
	}

	// Sucuri.
	if headers.Get("X-Sucuri-ID") != "" || strings.Contains(bodyLower, "sucuri") {
		return "Sucuri"
	}

	// Barracuda.
	if headers.Get("barra_counter_session") != "" {
		return "Barracuda"
	}

	// DenyAll.
	if headers.Get("X-DenyAll-ID") != "" {
		return "DenyAll"
	}

	return ""
}

// identifyTechnology identifies additional technology from X-Powered-By and
// other informational headers.
func identifyTechnology(poweredBy string, headers http.Header) string {
	if poweredBy == "" {
		return ""
	}

	poweredByLower := strings.ToLower(poweredBy)

	switch {
	case strings.Contains(poweredByLower, "php"):
		return "PHP"
	case strings.Contains(poweredByLower, "asp.net"):
		return "ASP.NET"
	case strings.Contains(poweredByLower, "express"):
		return "Express"
	case strings.Contains(poweredByLower, "next.js"):
		return "Next.js"
	case strings.Contains(poweredByLower, "django"):
		return "Django"
	case strings.Contains(poweredByLower, "flask"):
		return "Flask"
	case strings.Contains(poweredByLower, "rails"):
		return "Ruby on Rails"
	case strings.Contains(poweredByLower, "spring"):
		return "Spring"
	default:
		return poweredBy
	}
}
