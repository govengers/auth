// Package redirect validates where the library may send a browser or a credential and where it serves
// routes: same-origin return paths, login locations carrying a return path, configured external URLs and
// redirect targets, the endpoints of identity providers and route path prefixes. Every function is safe
// for concurrent use; all but To are pure.
package redirect

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

// returnParameter is the query parameter that carries the return path to a login route.
const returnParameter = "return_to"

const maximumReturnPathLength = 2048

// pathPrefixPattern is "/"-separated segments of unreserved URL characters: no trailing "/", no query, no
// ServeMux wildcard.
var pathPrefixPattern = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)

// SafeReturnPath accepts only same-origin relative paths: starts with "/", second byte not "/" or "\",
// no control characters or "\" anywhere, url.Parse succeeds with empty Scheme, Host and Opaque, <= 2048 bytes.
// Returns the path as sent plus "?"+RawQuery when present (fragment dropped).
func SafeReturnPath(raw string) (string, bool) {
	if !hasSafeShape(raw) {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.Opaque != "" {
		return "", false
	}
	return pathWithQuery(raw, parsed.RawQuery), true
}

// ReturnPath returns SafeReturnPath(request query return_to) or "/".
func ReturnPath(request *http.Request) string {
	returnPath, ok := SafeReturnPath(request.URL.Query().Get(returnParameter))
	if !ok {
		return "/"
	}
	return returnPath
}

// LoginLocation appends return_to=<returnPath> to loginURL (keeps an existing query); empty returnPath appends nothing.
func LoginLocation(loginURL, returnPath string) string {
	if returnPath == "" {
		return loginURL
	}
	return WithQuery(loginURL, url.Values{returnParameter: {returnPath}})
}

// WithQuery appends the encoded values to target, keeping a query target already has.
func WithQuery(target string, values url.Values) string {
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return target + separator + values.Encode()
}

// To answers 302 Found to location with Cache-Control no-store.
func To(writer http.ResponseWriter, location string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Location", location)
	writer.WriteHeader(http.StatusFound)
}

// ExternalURL validates an absolute http(s) URL without user info, query or fragment and trims a trailing "/".
// Errors never repeat the value, so a misplaced credential does not end up in a log.
func ExternalURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", errors.New("external URL must be an absolute http or https URL")
	}
	if parsed.User != nil || strings.ContainsAny(raw, "?#") {
		return "", errors.New("external URL must not contain user info, a query or a fragment")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

// AbsoluteTarget validates a configured redirect target (a provider's ErrorURL or PostLogoutURL) and
// returns it absolute: a same-origin path (SafeReturnPath) is prefixed with externalURL (an ExternalURL
// result), so a forward-auth redirect reaches the browser unchanged; an absolute http(s) URL is kept. A
// fragment is refused, so a query appended later (ErrorURL?code=...) stays in the query. Errors never
// repeat the value.
func AbsoluteTarget(raw, externalURL string) (string, error) {
	if !strings.Contains(raw, "#") {
		if returnPath, ok := SafeReturnPath(raw); ok {
			return externalURL + returnPath, nil
		}
		if isAbsoluteHTTPURL(raw) {
			return raw, nil
		}
	}
	return "", errors.New("must be a path starting with \"/\" or an absolute http(s) URL, without a fragment")
}

// IsPathPrefix reports whether prefix can prefix a provider's routes: "/"-separated segments of unreserved
// URL characters (A-Z a-z 0-9 . _ ~ -), no trailing "/", and no "." or ".." segment that path cleaning
// would remove, so the routes are neither ServeMux wildcards nor unreachable.
func IsPathPrefix(prefix string) bool {
	return pathPrefixPattern.MatchString(prefix) && path.Clean(prefix) == prefix
}

// IsTarget reports whether raw is a valid redirect target that takes a query: a same-origin path
// (SafeReturnPath) or an absolute http(s) URL with a host, without a fragment (AbsoluteTarget's rule).
func IsTarget(raw string) bool {
	_, err := AbsoluteTarget(raw, "")
	return err == nil
}

// isAbsoluteHTTPURL reports whether raw parses as an http or https URL with a host name.
func isAbsoluteHTTPURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != ""
}

// IsSecureURL reports whether raw is an absolute https URL with a host name, or an http URL on a loopback
// host (localhost, 127.0.0.0/8, ::1), without user info: credentials never travel in clear text, tests run
// on 127.0.0.1 (design D16).
func IsSecureURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return false
	}
	return parsed.Scheme == "https" || (parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()))
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// hasSafeShape checks the raw bytes before parsing: browsers read "//" and "/\" as another host and
// strip tabs and newlines, so "/\t/evil" would become "//evil".
func hasSafeShape(raw string) bool {
	if len(raw) > maximumReturnPathLength || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return false
	}
	return !strings.ContainsFunc(raw, isForbiddenInReturnPath)
}

func isForbiddenInReturnPath(character rune) bool {
	return character == '\\' || unicode.IsControl(character)
}

// pathWithQuery keeps the path exactly as sent: decoding and re-escaping it turns "/%2F " into "//%20",
// which a browser reads as another host.
func pathWithQuery(raw, rawQuery string) string {
	withoutQuery := raw
	if end := strings.IndexAny(raw, "?#"); end >= 0 {
		withoutQuery = raw[:end]
	}
	if rawQuery == "" {
		return withoutQuery
	}
	return withoutQuery + "?" + rawQuery
}
