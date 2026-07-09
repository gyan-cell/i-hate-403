package calibrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// HTTPDoer is the interface required by the calibrator to send HTTP requests.
// This allows injecting custom clients or mocks for testing.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Calibrator captures baselines and computes tolerance bands for a target URL.
type Calibrator struct {
	client  HTTPDoer
	timeout context.Context // nolint — stored only for documentation; actual ctx passed per-call
	verbose bool
}

// NewCalibrator creates a new Calibrator.
// The doer is used to send HTTP requests, timeout is unused here (callers pass
// context with deadline), and verbose enables debug logging.
func NewCalibrator(doer HTTPDoer, verbose bool) *Calibrator {
	return &Calibrator{
		client:  doer,
		verbose: verbose,
	}
}

// CaptureBaseline sends a request to the target URL, captures the response
// signature, runs calibration probes, and returns a fully populated Baseline.
func (c *Calibrator) CaptureBaseline(ctx context.Context, method, targetURL string, headers map[string]string) (*Baseline, error) {
	// 1. Send the initial request to capture the blocked response.
	statusCode, contentLength, bodyHash, contentType, respHeaders, body, err := c.sendRequest(ctx, method, targetURL, headers)
	if err != nil {
		return nil, fmt.Errorf("capturing baseline for %s: %w", targetURL, err)
	}

	// 2. Extract scheme and host for calibration probes.
	scheme, host, err := extractSchemeHost(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parsing target URL %s: %w", targetURL, err)
	}

	// 3. Calibrate with random paths to compute tolerance band.
	tolerance, err := c.calibrateRandom(ctx, scheme, host, headers)
	if err != nil {
		return nil, fmt.Errorf("random calibration for %s: %w", targetURL, err)
	}

	// 4. Build initial baseline for fragment calibration.
	baseline := &Baseline{
		StatusCode:    statusCode,
		ContentLength: contentLength,
		BodyHash:      bodyHash,
		ContentType:   contentType,
		Headers:       respHeaders,
		Tolerance:     tolerance,
	}

	// 5. Check if fragment stripping is in effect.
	fragmentStripped := c.calibrateFragment(ctx, targetURL, baseline, headers)
	baseline.FragmentStripped = fragmentStripped

	// 6. Fingerprint the server/CDN/WAF.
	baseline.Fingerprint = IdentifyFingerprint(respHeaders, body)

	return baseline, nil
}

// calibrateRandom sends requests to 3 random UUID paths on the target host
// and computes a tolerance band from the response content lengths.
func (c *Calibrator) calibrateRandom(ctx context.Context, scheme, host string, headers map[string]string) (ToleranceBand, error) {
	const probeCount = 3

	lengths := make([]float64, 0, probeCount)
	statusCodes := make([]int, 0, probeCount)

	for i := 0; i < probeCount; i++ {
		randomPath := "/" + uuid.New().String()
		probeURL := scheme + "://" + host + randomPath

		statusCode, contentLength, _, _, _, _, err := c.sendRequest(ctx, http.MethodGet, probeURL, headers)
		if err != nil {
			return ToleranceBand{}, fmt.Errorf("random probe %d: %w", i+1, err)
		}

		lengths = append(lengths, float64(contentLength))
		statusCodes = append(statusCodes, statusCode)
	}

	// Compute mean and standard deviation.
	mean := computeMean(lengths)
	stddev := computeStdDev(lengths, mean)

	// Detect soft-404: all probes returned 200 (server returns 200 for non-existent paths).
	softNotFound := true
	for _, sc := range statusCodes {
		if sc != http.StatusOK {
			softNotFound = false
			break
		}
	}

	band := ToleranceBand{
		Mean:         mean,
		StdDev:       stddev,
		Min:          mean - 2*stddev,
		Max:          mean + 2*stddev,
		Samples:      probeCount,
		SoftNotFound: softNotFound,
	}

	return band, nil
}

// calibrateFragment tests whether the server strips URL fragments.
// It appends a fragment to the target URL and compares the response to baseline.
func (c *Calibrator) calibrateFragment(ctx context.Context, targetURL string, baseline *Baseline, headers map[string]string) bool {
	fragmentURL := targetURL + "#" + uuid.New().String()

	statusCode, contentLength, bodyHash, _, _, _, err := c.sendRequest(ctx, http.MethodGet, fragmentURL, headers)
	if err != nil {
		// On error, assume fragments are not stripped.
		return false
	}

	// If the response matches the baseline, the server strips fragments.
	return statusCode == baseline.StatusCode &&
		contentLength == baseline.ContentLength &&
		bodyHash == baseline.BodyHash
}

// sendRequest sends an HTTP request and returns the parsed response components.
func (c *Calibrator) sendRequest(ctx context.Context, method, targetURL string, headers map[string]string) (
	statusCode int, contentLength int64, bodyHash string, contentType string,
	respHeaders http.Header, body []byte, err error,
) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return 0, 0, "", "", nil, nil, fmt.Errorf("creating request for %s: %w", targetURL, err)
	}

	// Apply custom headers.
	for key, val := range headers {
		req.Header.Set(key, val)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, 0, "", "", nil, nil, fmt.Errorf("sending request to %s: %w", targetURL, err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, "", "", nil, nil, fmt.Errorf("reading response body from %s: %w", targetURL, err)
	}

	statusCode = resp.StatusCode
	contentLength = int64(len(body))
	bodyHash = hashBody(body)
	contentType = resp.Header.Get("Content-Type")
	respHeaders = resp.Header.Clone()

	return statusCode, contentLength, bodyHash, contentType, respHeaders, body, nil
}

// hashBody returns the SHA-256 hex digest of the given body bytes.
func hashBody(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// extractSchemeHost extracts the scheme and host from a URL string.
func extractSchemeHost(rawURL string) (scheme, host string, err error) {
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 {
		return "", "", fmt.Errorf("missing scheme in URL %q", rawURL)
	}
	scheme = rawURL[:schemeEnd]
	rest := rawURL[schemeEnd+3:]

	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		host = rest
	} else {
		host = rest[:slashIdx]
	}

	if host == "" {
		return "", "", fmt.Errorf("empty host in URL %q", rawURL)
	}

	return scheme, host, nil
}

// computeMean calculates the arithmetic mean of a float64 slice.
func computeMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// computeStdDev calculates the population standard deviation given a mean.
func computeStdDev(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sumSq := 0.0
	for _, v := range values {
		diff := v - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(values)))
}
