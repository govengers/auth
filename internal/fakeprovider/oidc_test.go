package fakeprovider_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeprovider"
)

const (
	redirectURI  = "http://app.test/callback"
	codeVerifier = "a-long-random-code-verifier-for-the-test-0123456789"
)

func startIssuer(t *testing.T) *fakeprovider.OIDCServer {
	t.Helper()
	return fakeprovider.StartOIDC(t, fakeprovider.OIDCOptions{
		ClientID: "client", ClientSecret: "secret",
		RedirectURIs: []string{redirectURI}, PostLogoutRedirectURIs: []string{"http://app.test/bye"},
		User: fakeprovider.OIDCUser{Subject: "sub-alice", SessionID: "sid-1", RealmRoles: []string{"admin"}},
	})
}

func noRedirects() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// hop is one response of the issuer, read and closed, as a browser sees it before following it.
type hop struct {
	status   int
	location string
	body     []byte
}

func get(t *testing.T, target string) hop {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)
	response, err := noRedirects().Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }() // read-only response, close error carries no information
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return hop{status: response.StatusCode, location: response.Header.Get("Location"), body: body}
}

func validParameters() url.Values {
	digest := sha256.Sum256([]byte(codeVerifier))
	return url.Values{
		"client_id": {"client"}, "redirect_uri": {redirectURI}, "response_type": {"code"}, "scope": {"openid email"},
		"state": {"s1"}, "nonce": {"n1"}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])},
	}
}

func authorize(t *testing.T, issuer *fakeprovider.OIDCServer, parameters url.Values) hop {
	t.Helper()
	return get(t, issuer.IssuerURL()+"/authorize?"+parameters.Encode())
}

func codeFrom(t *testing.T, response hop) string {
	t.Helper()
	require.Equal(t, http.StatusFound, response.status)
	location, err := url.Parse(response.location)
	require.NoError(t, err)
	require.Equal(t, "s1", location.Query().Get("state"))
	return location.Query().Get("code")
}

func exchange(t *testing.T, issuer *fakeprovider.OIDCServer, code, verifier string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer.IssuerURL()+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("client", "secret")
	response, err := noRedirects().Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }() // read-only response, close error carries no information
	var body map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	return response.StatusCode, body
}

func payload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(decoded, &claims))
	return claims
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	issuer := startIssuer(t)

	status, body := exchange(t, issuer, codeFrom(t, authorize(t, issuer, validParameters())), codeVerifier)

	require.Equal(t, http.StatusOK, status)
	identityClaims := payload(t, body["id_token"].(string))
	require.Equal(t, "n1", identityClaims["nonce"])
	require.Equal(t, "sub-alice", identityClaims["sub"])
	require.Equal(t, "sid-1", identityClaims["sid"])
	require.Equal(t, issuer.IssuerURL(), identityClaims["iss"])
	accessClaims := payload(t, body["access_token"].(string))
	require.Equal(t, map[string]any{"roles": []any{"admin"}}, accessClaims["realm_access"])
}

func TestTheTokenEndpointRejectsAWrongVerifierAndAReusedCode(t *testing.T) {
	issuer := startIssuer(t)

	status, _ := exchange(t, issuer, codeFrom(t, authorize(t, issuer, validParameters())), "not-the-verifier")
	require.Equal(t, http.StatusBadRequest, status)

	code := codeFrom(t, authorize(t, issuer, validParameters()))
	status, _ = exchange(t, issuer, code, codeVerifier)
	require.Equal(t, http.StatusOK, status)
	status, _ = exchange(t, issuer, code, codeVerifier)
	require.Equal(t, http.StatusBadRequest, status, "a code works once")
}

func TestAuthorizeRejectsAClientThatSkipsPKCEStateOrNonce(t *testing.T) {
	issuer := startIssuer(t)
	for _, omitted := range []string{"code_challenge", "state", "nonce", "scope"} {
		t.Run(omitted, func(t *testing.T) {
			parameters := validParameters()
			parameters.Del(omitted)

			response := authorize(t, issuer, parameters)

			require.Equal(t, http.StatusFound, response.status)
			require.Contains(t, response.location, "error=invalid_request")
		})
	}
}

func TestAuthorizeNeverRedirectsToAnUnregisteredURI(t *testing.T) {
	issuer := startIssuer(t)
	parameters := validParameters()
	parameters.Set("redirect_uri", "http://evil.test/callback")

	require.Equal(t, http.StatusBadRequest, authorize(t, issuer, parameters).status)
}

func TestEndSessionRecordsTheHintAndRedirectsOnlyToARegisteredURI(t *testing.T) {
	issuer := startIssuer(t)

	registered := get(t, issuer.IssuerURL()+"/end_session?id_token_hint=hint-1&post_logout_redirect_uri=http://app.test/bye&state=x")
	unregistered := get(t, issuer.IssuerURL()+"/end_session?post_logout_redirect_uri=http://evil.test/")

	require.Equal(t, http.StatusFound, registered.status)
	require.Equal(t, "http://app.test/bye?state=x", registered.location)
	require.Equal(t, http.StatusOK, unregistered.status)
	require.Equal(t, []string{"hint-1"}, issuer.IDTokenHints())
}

func TestDiscoveryCanOmitTheEndSessionEndpoint(t *testing.T) {
	testCases := []struct {
		name string
		omit bool
	}{
		{name: "with end session", omit: false},
		{name: "without end session", omit: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			issuer := fakeprovider.StartOIDC(t, fakeprovider.OIDCOptions{ClientID: "client", ClientSecret: "secret", OmitEndSessionEndpoint: testCase.omit})
			var document map[string]any
			require.NoError(t, json.Unmarshal(get(t, issuer.IssuerURL()+"/.well-known/openid-configuration").body, &document))

			_, found := document["end_session_endpoint"]

			require.Equal(t, !testCase.omit, found)
			require.Equal(t, issuer.IssuerURL(), document["issuer"])
		})
	}
}

func TestNewOIDCHandlerValidatesOptions(t *testing.T) {
	_, err := fakeprovider.NewOIDCHandler(&fakeprovider.OIDCOptions{IssuerURL: "relative", ClientID: "client", ClientSecret: "secret"})
	require.Error(t, err)
	_, err = fakeprovider.NewOIDCHandler(&fakeprovider.OIDCOptions{IssuerURL: "http://127.0.0.1:1"})
	require.Error(t, err)
}

func TestTheIssuerKeepsNoSliceOrMapOfTheCaller(t *testing.T) {
	options := fakeprovider.OIDCOptions{
		ClientID: "client", ClientSecret: "secret",
		RedirectURIs: []string{redirectURI}, PostLogoutRedirectURIs: []string{"http://app.test/bye"},
		User: fakeprovider.OIDCUser{
			Subject: "sub-alice", RealmRoles: []string{"admin"}, ClientRoles: []string{"editor"}, Groups: []string{"/staff"},
			Attributes: map[string][]string{"team": {"chassis"}},
		},
		KeycloakRealm: "staff", KeycloakClientID: "service", KeycloakClientSecret: "service-secret",
	}
	issuer := fakeprovider.StartOIDC(t, options)

	options.RedirectURIs[0], options.PostLogoutRedirectURIs[0] = "http://evil.test/callback", "http://evil.test/bye"
	options.User.RealmRoles[0], options.User.ClientRoles[0], options.User.Groups[0] = "changed", "changed", "/changed"
	options.User.Attributes["team"][0] = "changed"
	options.User.Attributes["added"] = []string{"changed"}

	status, body := exchange(t, issuer, codeFrom(t, authorize(t, issuer, validParameters())), codeVerifier)
	require.Equal(t, http.StatusOK, status)
	accessClaims := payload(t, body["access_token"].(string))
	require.Equal(t, map[string]any{"roles": []any{"admin"}}, accessClaims["realm_access"])
	require.Equal(t, map[string]any{"client": map[string]any{"roles": []any{"editor"}}}, accessClaims["resource_access"])
	require.Equal(t, []any{"/staff"}, accessClaims["groups"])
	require.Equal(t, "http://app.test/bye", get(t, issuer.IssuerURL()+"/end_session?post_logout_redirect_uri=http://app.test/bye").location)
	require.Equal(t, map[string]any{"team": []any{"chassis"}}, keycloakAttributes(t, issuer))
}

// keycloakAttributes reads the user's attributes from the Admin API of the issuer's realm "staff".
func keycloakAttributes(t *testing.T, issuer *fakeprovider.OIDCServer) any {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"service"}, "client_secret": {"service-secret"}}
	tokenRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer.URL()+"/realms/staff/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse, err := noRedirects().Do(tokenRequest)
	require.NoError(t, err)
	defer func() { _ = tokenResponse.Body.Close() }() // read-only response, close error carries no information
	var token struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(tokenResponse.Body).Decode(&token))
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, issuer.URL()+"/admin/realms/staff/users/sub-alice", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, err := noRedirects().Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }() // read-only response, close error carries no information
	var user map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&user))
	return user["attributes"]
}
