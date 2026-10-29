package redirect

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeReturnPath(t *testing.T) {
	testCases := []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{name: "root", raw: "/", want: "/", wantOK: true},
		{name: "path", raw: "/dashboard", want: "/dashboard", wantOK: true},
		{name: "path with query", raw: "/dashboard?tab=2&x=y", want: "/dashboard?tab=2&x=y", wantOK: true},
		{name: "fragment dropped", raw: "/dashboard?tab=2#section", want: "/dashboard?tab=2", wantOK: true},
		{name: "empty query dropped", raw: "/dashboard?", want: "/dashboard", wantOK: true},
		{name: "encoded slash stays encoded", raw: "/%2Fevil.example", want: "/%2Fevil.example", wantOK: true},
		{name: "encoded slash and space stay as sent", raw: "/%2F ", want: "/%2F ", wantOK: true},
		{name: "encoded slash and host stay as sent", raw: "/%2Fevil.example%20?a", want: "/%2Fevil.example%20?a", wantOK: true},
		{name: "space kept", raw: "/a b", want: "/a b", wantOK: true},
		{name: "non-ASCII kept", raw: "/ä", want: "/ä", wantOK: true},
		{name: "question mark in query", raw: "/a??b", want: "/a??b", wantOK: true},
		{name: "colon in path", raw: "/a:b", want: "/a:b", wantOK: true},
		{name: "parent segments stay on the origin", raw: "/../../evil", want: "/../../evil", wantOK: true},
		{name: "maximum length", raw: "/" + strings.Repeat("a", 2047), want: "/" + strings.Repeat("a", 2047), wantOK: true},
		{name: "empty", raw: ""},
		{name: "relative", raw: "dashboard"},
		{name: "protocol relative", raw: "//evil.example"},
		{name: "protocol relative with path", raw: "//evil.example/path"},
		{name: "backslash host", raw: "/\\evil.example"},
		{name: "backslash later", raw: "/a\\b"},
		{name: "absolute https", raw: "https://evil.example"},
		{name: "javascript scheme", raw: "javascript:alert(1)"},
		{name: "tab before slash", raw: "/\t/evil.example"},
		{name: "newline", raw: "/a\nb"},
		{name: "carriage return line feed", raw: "/a\r\nSet-Cookie: x=y"},
		{name: "null byte", raw: "/a\x00b"},
		{name: "delete character", raw: "/a\x7fb"},
		{name: "C1 control character", raw: "/a\u0085b"},
		{name: "too long", raw: "/" + strings.Repeat("a", 2048)},
		{name: "invalid escape", raw: "/%zz"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := SafeReturnPath(testCase.raw)
			require.Equal(t, testCase.wantOK, ok)
			require.Equal(t, testCase.want, got)
		})
	}
}

func FuzzSafeReturnPath(f *testing.F) {
	for _, seed := range []string{"/", "/a?b=c#d", "//evil", "/\\evil", "/%2F%2Fevil", "/\t/evil", "https://evil", "/a b?c d", "/ä", "/%2F "} {
		f.Add(seed)
	}
	base, err := url.Parse("https://app.example/current/page")
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, raw string) {
		returnPath, ok := SafeReturnPath(raw)
		if !ok {
			require.Empty(t, returnPath)
			return
		}
		require.LessOrEqual(t, len(returnPath), maximumReturnPathLength)
		require.True(t, strings.HasPrefix(returnPath, "/"))
		require.False(t, strings.HasPrefix(returnPath, "//"))
		require.NotContains(t, returnPath, "\\")
		require.False(t, strings.ContainsFunc(returnPath, isForbiddenInReturnPath))

		parsed, err := url.Parse(returnPath)
		require.NoError(t, err)
		require.Empty(t, parsed.Scheme)
		require.Empty(t, parsed.Host)
		require.Empty(t, parsed.Opaque)

		resolved := base.ResolveReference(parsed)
		require.Equal(t, "https", resolved.Scheme)
		require.Equal(t, "app.example", resolved.Host)
	})
}

func TestReturnPath(t *testing.T) {
	testCases := []struct {
		name   string
		target string
		want   string
	}{
		{name: "safe path", target: "/login?return_to=%2Fdashboard%3Ftab%3D2", want: "/dashboard?tab=2"},
		{name: "missing", target: "/login", want: "/"},
		{name: "empty", target: "/login?return_to=", want: "/"},
		{name: "protocol relative", target: "/login?return_to=%2F%2Fevil.example", want: "/"},
		{name: "backslash", target: "/login?return_to=%2F%5Cevil.example", want: "/"},
		{name: "absolute", target: "/login?return_to=https%3A%2F%2Fevil.example", want: "/"},
		{name: "control character", target: "/login?return_to=%2F%09%2Fevil.example", want: "/"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testCase.target, nil)
			require.Equal(t, testCase.want, ReturnPath(request))
		})
	}
}

func TestLoginLocation(t *testing.T) {
	testCases := []struct {
		name       string
		loginURL   string
		returnPath string
		want       string
	}{
		{name: "no return path", loginURL: "/auth/login", want: "/auth/login"},
		{name: "appends query", loginURL: "/auth/login", returnPath: "/dashboard?tab=2", want: "/auth/login?return_to=%2Fdashboard%3Ftab%3D2"},
		{name: "keeps existing query", loginURL: "https://app.example/login?lang=de", returnPath: "/a", want: "https://app.example/login?lang=de&return_to=%2Fa"},
		{name: "hash route", loginURL: "https://app.example/#/login", returnPath: "/a", want: "https://app.example/#/login?return_to=%2Fa"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, LoginLocation(testCase.loginURL, testCase.returnPath))
		})
	}
}

func TestLoginLocationRoundTripsThroughReturnPath(t *testing.T) {
	location := LoginLocation("/auth/login", "/dashboard?tab=2&x=a%20b")
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, location, nil)
	require.Equal(t, "/dashboard?tab=2&x=a%20b", ReturnPath(request))
}

func TestExternalURL(t *testing.T) {
	testCases := []struct {
		name      string
		raw       string
		want      string
		wantError bool
	}{
		{name: "https", raw: "https://auth.example", want: "https://auth.example"},
		{name: "trailing slash trimmed", raw: "https://auth.example/", want: "https://auth.example"},
		{name: "path kept", raw: "https://app.example/auth/", want: "https://app.example/auth"},
		{name: "http with port", raw: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{name: "empty", raw: "", wantError: true},
		{name: "relative", raw: "/auth", wantError: true},
		{name: "no scheme", raw: "auth.example", wantError: true},
		{name: "other scheme", raw: "ftp://auth.example", wantError: true},
		{name: "opaque", raw: "https:auth.example", wantError: true},
		{name: "port without host", raw: "https://:443", wantError: true},
		{name: "query", raw: "https://auth.example/?a=b", wantError: true},
		{name: "empty query", raw: "https://auth.example/?", wantError: true},
		{name: "fragment", raw: "https://auth.example/#a", wantError: true},
		{name: "empty fragment", raw: "https://auth.example/#", wantError: true},
		{name: "user info", raw: "https://user:secret@auth.example", wantError: true},
		{name: "does not parse", raw: "https://auth.example/%zz", wantError: true},
		{name: "control character", raw: "https://auth.example/\n", wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := ExternalURL(testCase.raw)
			if testCase.wantError {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "secret")
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.want, got)
		})
	}
}

func TestIsSecureURL(t *testing.T) {
	testCases := []struct {
		raw  string
		want bool
	}{
		{raw: "https://idp.example.com/realms/x", want: true},
		{raw: "https://idp.example.com/?a=b", want: true},
		{raw: "http://127.0.0.1:8080", want: true},
		{raw: "http://127.0.0.2:8080", want: true},
		{raw: "http://[::1]:8080", want: true},
		{raw: "http://localhost:8080", want: true},
		{raw: "http://idp.example.com", want: false},
		{raw: "http://LOCALHOST:8080", want: false},
		{raw: "http://[::1%25lo0]:8080", want: false},
		{raw: "ftp://idp.example.com", want: false},
		{raw: "https://", want: false},
		{raw: "https://user@idp.example.com", want: false},
		{raw: "http://user:secret@127.0.0.1", want: false},
		{raw: "/realms/x", want: false},
		{raw: "::", want: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.raw, func(t *testing.T) {
			require.Equal(t, testCase.want, IsSecureURL(testCase.raw))
		})
	}
}

func TestIsTarget(t *testing.T) {
	testCases := []struct {
		raw  string
		want bool
	}{
		{raw: "/", want: true},
		{raw: "/login?lang=de", want: true},
		{raw: "https://app.example/login", want: true},
		{raw: "http://app.example", want: true},
		{raw: "", want: false},
		{raw: "login", want: false},
		{raw: "//evil.example", want: false},
		{raw: "/\\evil.example", want: false},
		{raw: "https://", want: false},
		{raw: "https:app.example", want: false},
		{raw: "javascript:alert(1)", want: false},
		{raw: "ftp://app.example", want: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.raw, func(t *testing.T) {
			require.Equal(t, testCase.want, IsTarget(testCase.raw))
		})
	}
}

func TestIsAbsoluteHTTPURL(t *testing.T) {
	testCases := []struct {
		raw  string
		want bool
	}{
		{raw: "https://idp.example/logout?x=1", want: true},
		{raw: "http://127.0.0.1:8080", want: true},
		{raw: "/logout", want: false},
		{raw: "https://", want: false},
		{raw: "ftp://idp.example", want: false},
		{raw: "https://idp.example/%zz", want: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.raw, func(t *testing.T) {
			require.Equal(t, testCase.want, IsAbsoluteHTTPURL(testCase.raw))
		})
	}
}

func TestWithQuery(t *testing.T) {
	require.Equal(t, "https://app.example.com/error?code=login_failed", WithQuery("https://app.example.com/error", url.Values{"code": {"login_failed"}}))
	require.Equal(t, "/login?x=1&code=forbidden", WithQuery("/login?x=1", url.Values{"code": {"forbidden"}}))
	require.Equal(t, "/logout?a=1&b=x+y%26z", WithQuery("/logout", url.Values{"b": {"x y&z"}, "a": {"1"}}))
}

func TestTo(t *testing.T) {
	recorder := httptest.NewRecorder()
	To(recorder, "/dashboard?tab=2")
	require.Equal(t, http.StatusFound, recorder.Code)
	require.Equal(t, "/dashboard?tab=2", recorder.Header().Get("Location"))
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
}

func TestAbsoluteTarget(t *testing.T) {
	const external = "https://app.example/base"
	testCases := []struct {
		name      string
		raw       string
		want      string
		wantError bool
	}{
		{name: "path made absolute", raw: "/login?source=github", want: external + "/login?source=github"},
		{name: "root path", raw: "/", want: external + "/"},
		{name: "empty query dropped", raw: "/login?", want: external + "/login"},
		{name: "absolute kept", raw: "https://www.example/goodbye?x=1", want: "https://www.example/goodbye?x=1"},
		{name: "empty", raw: "", wantError: true},
		{name: "relative", raw: "login", wantError: true},
		{name: "protocol relative", raw: "//evil.example/login", wantError: true},
		{name: "backslash host", raw: "/\\evil.example", wantError: true},
		{name: "javascript", raw: "javascript:alert(1)", wantError: true},
		{name: "path with fragment", raw: "/login#failed", wantError: true},
		{name: "absolute with fragment", raw: "https://www.example/#/error", wantError: true},
		{name: "empty fragment", raw: "/login#", wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := AbsoluteTarget(testCase.raw, external)
			if testCase.wantError {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.want, got)
		})
	}
}
