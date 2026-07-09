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
	// Clamp dial/TLS timeouts to the configured request timeout so that a
	// short user-supplied timeout (e.g. 5s) is respected at the TCP level
	// and does not hang for the transport's default 30s.
	dialTimeout := cfg.Timeout
	if dialTimeout <= 0 {
		dialTimeout = 30 * time.Second
	}
	tlsTimeout := dialTimeout

	t := &http.Transport{
		// Connection pooling settings.
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,

		// TLS and response timeouts honour the per-request timeout.
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: cfg.Timeout,

		// Dialer timeout also honours the per-request timeout.
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// TLS configuration.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // intentional for bypass testing
		},
	}

	// Configure proxy if provided, otherwise fall back to environment.
	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err == nil {
			t.Proxy = http.ProxyURL(proxyURL)
		}
	} else {
		t.Proxy = http.ProxyFromEnvironment
	}

	return t
}
