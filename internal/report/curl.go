package report

import (
	"fmt"
	"strings"

	"github.com/gyan-cell/i-hate-403/internal/bypass"
)

// BuildCurlCommand constructs a reproducible curl command string for the given payload.
func BuildCurlCommand(p bypass.Payload, proxyURL string, insecure bool) string {
	var parts []string
	parts = append(parts, "curl")

	if insecure {
		parts = append(parts, "-k")
	}

	if proxyURL != "" {
		parts = append(parts, "-x", ShellEscape(proxyURL))
	}

	if p.Method != "" && p.Method != "GET" {
		parts = append(parts, "-X", p.Method)
	}

	// Sort headers for deterministic output.
	for k, v := range p.Headers {
		parts = append(parts, "-H", ShellEscape(fmt.Sprintf("%s: %s", k, v)))
	}

	if p.Body != "" {
		parts = append(parts, "-d", ShellEscape(p.Body))
	}

	if len(p.CurlArgs) > 0 {
		parts = append(parts, p.CurlArgs...)
	}

	parts = append(parts, "-s", "-o", "/dev/null", "-w",
		ShellEscape("%{http_code} %{size_download}"))

	targetURL := p.URL
	if p.RawURL != "" {
		targetURL = p.RawURL
	}
	parts = append(parts, ShellEscape(targetURL))

	return strings.Join(parts, " ")
}

// ShellEscape wraps a string in single quotes for safe use in shell commands,
// properly escaping any embedded single quotes.
func ShellEscape(s string) string {
	if s == "" {
		return "''"
	}

	// Check if the string contains any characters that need quoting.
	needsQuoting := false
	for _, c := range s {
		if c == ' ' || c == '\'' || c == '"' || c == '\\' || c == '$' ||
			c == '!' || c == '`' || c == '(' || c == ')' || c == '{' ||
			c == '}' || c == '[' || c == ']' || c == '|' || c == '&' ||
			c == ';' || c == '<' || c == '>' || c == '~' || c == '#' ||
			c == '*' || c == '?' || c == '\n' || c == '\t' || c == '%' {
			needsQuoting = true
			break
		}
	}

	if !needsQuoting {
		return s
	}

	// Wrap in single quotes, escaping embedded single quotes with '\'' pattern.
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
