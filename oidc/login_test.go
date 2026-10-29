package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
	"github.com/govengers/auth/oidc"
)

var errProvisioning = errors.New("provisioning failed")

func TestLoginRedirectsToTheIssuerWithStateNonceAndS256Challenge(t *testing.T) {
	issuer := startIssuer(t, nil)
	application := newApplication(t, issuer, nil)

	response := newBrowser(t).get(application.handler, prefix+"/login", nil)

	require.Equal(t, http.StatusFound, response.Code)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	location := response.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, issuer.IssuerURL()+"/authorize?"), location)
	query := queryOf(t, location)
	require.Equal(t, "code", query.Get("response_type"))
	require.Equal(t, clientID, query.Get("client_id"))
	require.Equal(t, externalURL+prefix+"/callback", query.Get("redirect_uri"))
	require.Equal(t, "openid profile email", query.Get("scope"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.Len(t, query.Get("code_challenge"), 43)
	require.Len(t, query.Get("state"), 43)
	require.Len(t, query.Get("nonce"), 43)
	require.Equal(t, auth.Outcome{Provider: providerName, Action: auth.ActionLogin, Result: auth.ResultSuccess}, application.outcomes.last(t))
}

func TestCallbackStartsARotatedSessionAndRedirectsToTheReturnPath(t *testing.T) {
	application := newApplication(t, startIssuer(t, nil), nil)
	person := newBrowser(t)
	callback := person.toCallback(application, prefix+"/login?return_to=%2Fdashboard%3Ftab%3D2")
	loginCookie := person.cookies["auth_session"].Value

	response := person.get(application.handler, callback, nil)

	require.Equal(t, http.StatusFound, response.Code, response.Body.String())
	require.Equal(t, externalURL+"/dashboard?tab=2", response.Header().Get("Location"))
	require.NotEqual(t, loginCookie, person.cookies["auth_session"].Value, "the session ID rotates at login")
	require.Contains(t, person.sessionValue(application.store, providerName+".id_token"), ".")
	current := person.get(application.handler, "/me", nil)
	require.Equal(t, http.StatusOK, current.Code)
	var identity auth.IdentityResponse
	require.NoError(t, json.Unmarshal(current.Body.Bytes(), &identity))
	require.Equal(t, auth.IdentityResponse{
		Provider: providerName, Subject: "user-1", Username: "ada", Name: "Ada Lovelace", Email: "ada@example.com",
		Picture: "https://example.com/ada.png", Active: true, Roles: []string{},
		OIDCRoles: []string{"admin"}, OIDCClientRoles: []string{"editor"}, Groups: []string{"/staff"},
	}, identity)
	outcome := application.outcomes.last(t)
	require.Equal(t, auth.ActionCallback, outcome.Action)
	require.Equal(t, auth.ResultSuccess, outcome.Result)
	require.Equal(t, "idp-session-1", outcome.Identity.Claims["sid"])
}

func TestCallbackReturnsOnlyToSafePaths(t *testing.T) {
	application := newApplication(t, startIssuer(t, nil), nil)
	testCases := []struct {
		name     string
		returnTo string
		want     string
	}{
		{name: "path with query", returnTo: "/reports?year=2026&q=a%20b", want: "/reports?year=2026&q=a%20b"},
		{name: "none", returnTo: "", want: "/"},
		{name: "protocol-relative", returnTo: "//evil.example", want: "/"},
		{name: "backslash", returnTo: "/\\evil.example", want: "/"},
		{name: "absolute", returnTo: "https://evil.example/", want: "/"},
		{name: "control character", returnTo: "/\t/evil.example", want: "/"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			loginTarget := prefix + "/login"
			if testCase.returnTo != "" {
				loginTarget += "?return_to=" + url.QueryEscape(testCase.returnTo)
			}

			response := newBrowser(t).signIn(application, loginTarget)

			require.Equal(t, externalURL+testCase.want, response.Header().Get("Location"))
		})
	}
}

func TestCallbackRefusals(t *testing.T) {
	testCases := []struct {
		name       string
		faults     func(options *fakeprovider.OIDCOptions)
		callback   func(callback string) string
		replay     bool
		withoutJar bool
		wantStatus int
		wantCode   string
	}{
		{name: "state mismatch", callback: withParameter("state", "forged"), wantStatus: http.StatusBadRequest, wantCode: "state_mismatch"},
		{name: "no session cookie", withoutJar: true, wantStatus: http.StatusBadRequest, wantCode: "login_expired"},
		{name: "replayed callback", replay: true, wantStatus: http.StatusBadRequest, wantCode: "login_expired"},
		{name: "IdP error", callback: withParameter("error", "access_denied"), wantStatus: http.StatusUnauthorized, wantCode: "login_denied"},
		{name: "no code", callback: withParameter("code", ""), wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "code the IdP rejects", callback: withParameter("code", "forged"), wantStatus: http.StatusUnauthorized, wantCode: "login_failed"},
		{name: "nonce mismatch", faults: func(options *fakeprovider.OIDCOptions) { options.WrongNonce = true }, wantStatus: http.StatusUnauthorized, wantCode: "login_failed"},
		{name: "bad signature", faults: func(options *fakeprovider.OIDCOptions) { options.BadSignature = true }, wantStatus: http.StatusUnauthorized, wantCode: "login_failed"},
		{name: "no ID token", faults: func(options *fakeprovider.OIDCOptions) { options.OmitIDToken = true }, wantStatus: http.StatusUnauthorized, wantCode: "login_failed"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			application := newApplication(t, startIssuer(t, testCase.faults), nil)
			person := newBrowser(t)
			callback := person.toCallback(application, prefix+"/login")
			if testCase.callback != nil {
				callback = testCase.callback(callback)
			}
			if testCase.replay {
				require.Equal(t, http.StatusFound, person.get(application.handler, callback, nil).Code)
			}
			if testCase.withoutJar {
				person = newBrowser(t)
			}

			response := person.get(application.handler, callback, nil)

			require.Equal(t, testCase.wantStatus, response.Code, response.Body.String())
			require.JSONEq(t, `{"code":"`+testCase.wantCode+`","message":"`+messageOf(testCase.wantStatus)+`"}`, response.Body.String())
			if !testCase.replay {
				require.Equal(t, http.StatusUnauthorized, person.me(application), "no session")
			}
			outcome := application.outcomes.last(t)
			require.Equal(t, auth.ActionCallback, outcome.Action)
			require.Equal(t, auth.ResultDenied, outcome.Result)
			require.Error(t, outcome.Err)
		})
	}
}

func TestCallbackFailsWhenTheIssuerIsUnreachable(t *testing.T) {
	issuer := startIssuer(t, nil)
	transport := &failingTransport{failPath: "/token"}
	application := newApplication(t, issuer, func(options *oidc.Options) {
		options.HTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: transport}
	})

	response := newBrowser(t).signIn(application, prefix+"/login")

	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.JSONEq(t, `{"code":"internal","message":"internal error"}`, response.Body.String())
	require.Equal(t, auth.ResultError, application.outcomes.last(t).Result)
	require.Positive(t, transport.requests(), "discovery went through HTTPClient")
}

func TestCallbackClassifiesTokenEndpointErrorsWithoutTheirText(t *testing.T) {
	const marker = "alice@example.com"
	testCases := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantStatus  int
		wantResult  auth.Result
	}{
		{name: "refusal with a description", status: http.StatusBadRequest, contentType: "application/json", body: `{"error":"invalid_grant","error_description":"` + marker + `","error_uri":"https://idp.example.com/` + marker + `"}`, wantStatus: http.StatusUnauthorized, wantResult: auth.ResultDenied},
		{name: "refusal as a page", status: http.StatusUnauthorized, contentType: "text/html", body: "<p>" + marker + "</p>", wantStatus: http.StatusUnauthorized, wantResult: auth.ResultDenied},
		{name: "outage as a page", status: http.StatusServiceUnavailable, contentType: "text/html", body: "<p>" + marker + "</p>", wantStatus: http.StatusInternalServerError, wantResult: auth.ResultError},
		{name: "outage with an error code", status: http.StatusBadGateway, contentType: "application/json", body: `{"error":"temporarily_unavailable","error_description":"` + marker + `"}`, wantStatus: http.StatusInternalServerError, wantResult: auth.ResultError},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &answeringTransport{path: "/token", status: testCase.status, contentType: testCase.contentType, body: testCase.body}
			application := newApplication(t, startIssuer(t, nil), func(options *oidc.Options) {
				options.HTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: transport}
			})

			response := newBrowser(t).signIn(application, prefix+"/login")

			require.Equal(t, testCase.wantStatus, response.Code, response.Body.String())
			outcome := application.outcomes.last(t)
			require.Equal(t, testCase.wantResult, outcome.Result)
			require.ErrorContains(t, outcome.Err, "token endpoint answered HTTP "+strconv.Itoa(testCase.status))
			require.NotContains(t, outcome.Err.Error(), marker, "the IdP's free text stays out of outcomes and events")
		})
	}
}

func TestAllowedEmailDomains(t *testing.T) {
	testCases := []struct {
		name          string
		email         string
		emailVerified bool
		wantStatus    int
	}{
		{name: "allowed domain", email: "ada@example.com", emailVerified: true, wantStatus: http.StatusFound},
		{name: "domain in another case", email: "ada@Example.COM", emailVerified: true, wantStatus: http.StatusFound},
		{name: "second allowed domain", email: "ada@corp.example", emailVerified: true, wantStatus: http.StatusFound},
		{name: "other domain", email: "ada@evil.example", emailVerified: true, wantStatus: http.StatusForbidden},
		{name: "subdomain", email: "ada@sub.example.com", emailVerified: true, wantStatus: http.StatusForbidden},
		{name: "unverified", email: "ada@example.com", emailVerified: false, wantStatus: http.StatusForbidden},
		{name: "no email", email: "", emailVerified: true, wantStatus: http.StatusForbidden},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			issuer := startIssuer(t, func(options *fakeprovider.OIDCOptions) {
				options.User.Email, options.User.EmailVerified = testCase.email, testCase.emailVerified
			})
			application := newApplication(t, issuer, func(options *oidc.Options) { options.AllowedEmailDomains = []string{"EXAMPLE.com", "corp.example"} })

			response := newBrowser(t).signIn(application, prefix+"/login")

			require.Equal(t, testCase.wantStatus, response.Code)
			if testCase.wantStatus == http.StatusForbidden {
				require.JSONEq(t, `{"code":"forbidden","message":"access denied"}`, response.Body.String(), "the allowed domains stay server-side")
			}
		})
	}
}

func TestOnLogin(t *testing.T) {
	testCases := []struct {
		name       string
		hook       auth.Hook
		wantStatus int
		wantCode   string
		wantRoles  []string
	}{
		{name: "changes the stored identity", hook: grantRole("app-admin"), wantStatus: http.StatusFound, wantRoles: []string{"app-admin"}},
		{name: "refusal answers its kind", hook: refuseWith(&auth.Error{Kind: auth.ErrForbidden, Reason: "not provisioned"}), wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "failure answers 500", hook: refuseWith(errProvisioning), wantStatus: http.StatusInternalServerError, wantCode: "internal"},
		{name: "no identity answers 500", hook: refuseWith(nil), wantStatus: http.StatusInternalServerError, wantCode: "internal"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			application := newApplication(t, startIssuer(t, nil), func(options *oidc.Options) { options.OnLogin = testCase.hook })
			person := newBrowser(t)

			response := person.signIn(application, prefix+"/login")

			require.Equal(t, testCase.wantStatus, response.Code)
			outcome := application.outcomes.last(t)
			require.Equal(t, "user-1", outcome.Identity.Subject, "the outcome names the authenticated user")
			if testCase.wantCode != "" {
				require.Contains(t, response.Body.String(), `"code":"`+testCase.wantCode+`"`)
				require.Equal(t, http.StatusUnauthorized, person.me(application), "no session after a refused login")
				return
			}
			current := person.get(application.handler, "/me", nil)
			var identity auth.IdentityResponse
			require.NoError(t, json.Unmarshal(current.Body.Bytes(), &identity))
			require.Equal(t, testCase.wantRoles, identity.Roles)
		})
	}
}

func TestErrorURL(t *testing.T) {
	testCases := []struct {
		name         string
		errorURL     string
		callback     func(callback string) string
		wantLocation string
	}{
		{name: "path", errorURL: "/login?oidc=1", callback: withParameter("state", "forged"), wantLocation: externalURL + "/login?oidc=1&code=state_mismatch"},
		{name: "absolute URL", errorURL: "https://login.example.com/failed", callback: withParameter("error", "access_denied"), wantLocation: "https://login.example.com/failed?code=login_denied"},
		{name: "IdP rejects the code", errorURL: "/login", callback: withParameter("code", "forged"), wantLocation: externalURL + "/login?code=login_failed"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			application := newApplication(t, startIssuer(t, nil), func(options *oidc.Options) { options.ErrorURL = testCase.errorURL })
			person := newBrowser(t)

			response := person.get(application.handler, testCase.callback(person.toCallback(application, prefix+"/login")), nil)

			require.Equal(t, http.StatusFound, response.Code)
			require.Equal(t, testCase.wantLocation, response.Header().Get("Location"))
			require.Equal(t, auth.ResultDenied, application.outcomes.last(t).Result)
		})
	}
}

func TestErrorURLAlsoReceivesInternalFailures(t *testing.T) {
	application := newApplication(t, startIssuer(t, nil), func(options *oidc.Options) {
		options.ErrorURL = "/login"
		options.OnLogin = refuseWith(errProvisioning)
	})

	response := newBrowser(t).signIn(application, prefix+"/login")

	require.Equal(t, externalURL+"/login?code=internal", response.Header().Get("Location"))
	require.Equal(t, auth.ResultError, application.outcomes.last(t).Result)
}

func TestGoogleStyleLoginWithAnOpaqueAccessToken(t *testing.T) {
	issuer := startIssuer(t, func(options *fakeprovider.OIDCOptions) { options.OpaqueAccessToken = true })
	application := newApplication(t, issuer, func(options *oidc.Options) { options.ClaimMapper = oidc.GoogleClaimMapper })
	person := newBrowser(t)

	require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)

	var identity auth.IdentityResponse
	require.NoError(t, json.Unmarshal(person.get(application.handler, "/me", nil).Body.Bytes(), &identity))
	require.Equal(t, "ada", identity.Username, "the part of the email before @")
	require.Empty(t, identity.OIDCRoles, "an opaque access token carries no roles")
}

func TestTwoProvidersShareOneStore(t *testing.T) {
	store := newStore(t)
	first := newApplicationOn(t, store, startIssuer(t, nil), nil)
	secondIssuer := startIssuer(t, func(options *fakeprovider.OIDCOptions) {
		options.User.Subject = "user-2"
		options.RedirectURIs = []string{externalURL + "/auth/oidc/second/callback"}
	})
	second := newApplicationOn(t, store, secondIssuer, func(options *oidc.Options) { options.Name = "second" })
	handler := mount(t, store, first.provider, second.provider)
	person := newBrowser(t)

	require.Equal(t, http.StatusFound, person.get(handler, person.toCallback(first, prefix+"/login"), nil).Code)
	login := person.get(handler, "/auth/oidc/second/login", nil)
	require.Equal(t, http.StatusFound, person.get(handler, person.issuer(login.Header().Get("Location")), nil).Code)

	var identity auth.IdentityResponse
	require.NoError(t, json.Unmarshal(person.get(handler, "/me", nil).Body.Bytes(), &identity))
	require.Equal(t, "second", identity.Provider, "the second login replaced the first session")
	require.Equal(t, "user-2", identity.Subject)
	logout := person.get(handler, prefix+"/logout", nil)
	require.Equal(t, externalURL+"/", logout.Header().Get("Location"), "the first provider sends no hint for the second's session")
	require.Equal(t, http.StatusUnauthorized, person.get(handler, "/me", nil).Code)
}

func grantRole(role string) auth.Hook {
	return func(_ context.Context, identity *auth.Identity) (*auth.Identity, error) {
		changed := identity.Clone()
		changed.Roles = append(changed.Roles, role)
		return changed, nil
	}
}

func refuseWith(err error) auth.Hook {
	return func(context.Context, *auth.Identity) (*auth.Identity, error) {
		return nil, err
	}
}

// withParameter returns a change of a callback URL that sets name to value.
func withParameter(name, value string) func(callback string) string {
	return func(callback string) string {
		parsed, err := url.Parse(callback)
		if err != nil {
			return callback
		}
		query := parsed.Query()
		query.Set(name, value)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
}

func messageOf(status int) string {
	_, response := auth.ResponseFor(map[int]error{
		http.StatusBadRequest:   auth.ErrInvalidRequest,
		http.StatusUnauthorized: auth.ErrUnauthenticated,
		http.StatusForbidden:    auth.ErrForbidden,
	}[status])
	return response.Message
}

// failingTransport fails requests to failPath and counts the others.
type failingTransport struct {
	failPath string
	mutex    sync.Mutex
	passed   int
}

func (f *failingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, f.failPath) {
		return nil, errors.New("connection refused")
	}
	f.mutex.Lock()
	f.passed++
	f.mutex.Unlock()
	return http.DefaultTransport.RoundTrip(request)
}

func (f *failingTransport) requests() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.passed
}

// answeringTransport answers requests to path itself and passes the others on.
type answeringTransport struct {
	path        string
	status      int
	contentType string
	body        string
}

func (a *answeringTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !strings.HasSuffix(request.URL.Path, a.path) {
		return http.DefaultTransport.RoundTrip(request)
	}
	return &http.Response{
		Status: strconv.Itoa(a.status) + " " + http.StatusText(a.status), StatusCode: a.status,
		Header: http.Header{"Content-Type": {a.contentType}}, Body: io.NopCloser(strings.NewReader(a.body)), Request: request,
	}, nil
}
