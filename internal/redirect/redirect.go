// Package redirect validates where the library may send a browser or a credential: same-origin return
// paths, login locations carrying a return path, configured external URLs and the endpoints of identity
// providers. Every function is pure and safe for concurrent use.
package redirect

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// ReturnParameter is the query parameter that carries the return path to a login route.
const ReturnParameter = "return_to"

const maximumReturnPathLength = 2048

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
	returnPath, ok := SafeReturnPath(request.URL.Query().Get(ReturnParameter))
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
	separator := "?"
	if strings.Contains(loginURL, "?") {
		separator = "&"
	}
	return loginURL + separator + ReturnParameter + "=" + url.QueryEscape(returnPath)
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

// IsSecureURL reports whether raw is an absolute https URL, or an http URL on a loopback host (localhost,
// 127.0.0.0/8, ::1), without user info: credentials never travel in clear text, tests run on 127.0.0.1
// (design D16).
func IsSecureURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil {
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
	path := raw
	if end := strings.IndexAny(raw, "?#"); end >= 0 {
		path = raw[:end]
	}
	if rawQuery == "" {
		return path
	}
	return path + "?" + rawQuery
}
