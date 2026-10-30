//go:build e2e

package compose

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnAnonymousBrowserIsSentThroughTheIssuerWithPKCEStateAndNonce(t *testing.T) {
	person := newBrowser(t)

	toLogin := person.get(appURL+"/whoami?x=1", nil)
	require.Equal(t, http.StatusFound, toLogin.status)
	// absolute: Traefik resolves a relative Location against the internal forwardauth address
	require.Equal(t, appURL+"/auth/oidc/oidc/login?return_to=%2Fwhoami%3Fx%3D1", toLogin.location)

	toIssuer := person.get(toLogin.location, nil)
	require.Equal(t, http.StatusFound, toIssuer.status)
	require.True(t, strings.HasPrefix(toIssuer.location, issuerURL+"/authorize?"), toIssuer.location)
	query := queryOf(t, toIssuer.location)
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(t, query.Get("code_challenge"))
	require.NotEmpty(t, query.Get("state"))
	require.NotEmpty(t, query.Get("nonce"))
	require.Equal(t, appURL+"/auth/oidc/oidc/callback", query.Get("redirect_uri"))
}

func TestLoginEndsAtTheAppWhichSeesTheIdentityAsAVerifiableBearerToken(t *testing.T) {
	person := signIn(t, "/whoami?x=1")

	hop := person.get(appURL+"/whoami?x=1", nil)

	require.Equal(t, http.StatusOK, hop.status)
	identity := bearerIdentity(t, hop.body)
	require.Equal(t, "oidc", identity.Provider)
	require.NotEmpty(t, identity.Subject)
}

func TestAnAPICallWithoutSessionIs401JSON(t *testing.T) {
	hop := newBrowser(t).get(appURL+"/api/things", nil)

	require.Equal(t, http.StatusUnauthorized, hop.status)
	require.Contains(t, hop.header.Get("Content-Type"), "application/json")
	require.JSONEq(t, `{"code":"unauthenticated","message":"authentication required"}`, hop.body)
}

func TestAnAPICallWithASessionReachesTheApp(t *testing.T) {
	person := signIn(t, "/whoami")

	hop := person.get(appURL+"/api/things", nil)

	require.Equal(t, http.StatusOK, hop.status)
	require.Equal(t, "oidc", bearerIdentity(t, hop.body).Provider)
}

func TestAfterLogoutTheAppRedirectsToTheLoginAgain(t *testing.T) {
	person := signIn(t, "/whoami")

	toIssuer := person.get(appURL+"/auth/oidc/oidc/logout", nil)
	require.Equal(t, http.StatusFound, toIssuer.status)
	require.True(t, strings.HasPrefix(toIssuer.location, issuerURL+"/end_session?"), toIssuer.location)
	require.NotEmpty(t, queryOf(t, toIssuer.location).Get("id_token_hint"))
	backToApp := person.get(toIssuer.location, nil)
	require.Equal(t, http.StatusFound, backToApp.status)
	require.True(t, strings.HasPrefix(backToApp.location, appURL+"/"), backToApp.location)

	require.Equal(t, http.StatusFound, person.get(appURL+"/whoami", nil).status)
}

func TestAnAuthorizationHeaderFromTheClientNeverReachesTheApp(t *testing.T) {
	forged := http.Header{"Authorization": {"Bearer forged-by-the-client"}}

	anonymous := newBrowser(t).get(appURL+"/whoami", forged)
	require.Equal(t, http.StatusFound, anonymous.status, "a forged header is not a login")

	hop := signIn(t, "/whoami").get(appURL+"/whoami", forged)
	require.Equal(t, http.StatusOK, hop.status)
	require.NotContains(t, hop.body, "forged-by-the-client")
	bearerIdentity(t, hop.body)
}

func TestForwardedHeadersFromTheClientDoNotSteerTheRedirect(t *testing.T) {
	hop := newBrowser(t).get(appURL+"/whoami", http.Header{"X-Forwarded-Host": {"evil.example"}, "X-Forwarded-Proto": {"https"}, "X-Forwarded-Uri": {"/admin"}})

	require.Equal(t, http.StatusFound, hop.status)
	require.Equal(t, appURL+"/auth/oidc/oidc/login?return_to=%2Fwhoami", hop.location)
}

func TestACallbackWithAForgedStateIsRefused(t *testing.T) {
	person := newBrowser(t)
	toLogin := person.get(appURL+"/whoami", nil)
	toIssuer := person.get(toLogin.location, nil)
	toCallback := person.get(toIssuer.location, nil)

	forged := person.get(strings.Replace(toCallback.location, "state=", "state=forged", 1), nil)

	require.Equal(t, http.StatusBadRequest, forged.status)
	require.JSONEq(t, `{"code":"state_mismatch","message":"invalid request"}`, forged.body)
	require.Equal(t, http.StatusFound, person.get(appURL+"/whoami", nil).status, "still not logged in")
}

func TestTheChecksAndProbesAreNotRoutedToTheBrowser(t *testing.T) {
	person := signIn(t, "/whoami")

	for _, path := range []string{"/auth/ui", "/auth/api", "/auth/health", "/auth/ready"} {
		hop := person.get(appURL+path, nil)

		require.Equal(t, http.StatusNotFound, hop.status, path)
		require.Empty(t, hop.header.Get("Authorization"), "no bearer JWT for a script on the page")
	}
	require.Equal(t, http.StatusOK, person.get(appURL+"/auth/jwks", nil).status, "the JWKS stays public")
}
