package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// NewTransport creates a configured *http.Transport based on the provided Config.
// It sets up TLS verification, proxy routing, connection pooling, and timeouts.
func NewTransport(cfg Config) *http.Transport {
	t := &http.Transport{
		// Connection pooling settings.
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,

		// TLS and response timeouts.
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,

		// Standard dialer with reasonable timeouts.
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// TLS configuration.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // intentional for bypass testing
		},
	}

	// Configure proxy if provided.
	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err == nil {
			t.Proxy = http.ProxyURL(proxyURL)
		}
		// If proxy URL is malformed, silently fall back to no proxy.
		// This avoids panicking on bad user input.
	}

	return t
}
