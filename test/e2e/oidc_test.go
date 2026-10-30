//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeprovider"
)

const (
	testClientID     = "forwardauth"
	testClientSecret = "e2e-oidc-secret"
)

func startOIDC(t *testing.T, options fakeprovider.OIDCOptions) *fakeprovider.OIDCServer {
	t.Helper()
	options.ClientID, options.ClientSecret = testClientID, testClientSecret
	if options.User.PreferredUsername == "" {
		options.User = fakeprovider.OIDCUser{
			Subject: "alice-id", PreferredUsername: "alice", Email: "alice@example.com", EmailVerified: true, SessionID: "sid-1",
			RealmRoles: []string{"user"}, Groups: []string{"/staff"},
		}
	}
	return fakeprovider.StartOIDC(t, options)
}

func withJWT(t *testing.T, environment map[string]string) map[string]string {
	t.Helper()
	return merged(environment, map[string]string{"JWT_ENABLED": "true", "JWT_PRIVATE_KEY": privateKeyPEM(t), "JWT_AUDIENCE": jwtAudience})
}

func TestOIDCLoginReturnsToTheRequestedPageAndTheChecksHandOnAVerifiableJWT(t *testing.T) {
	issuer := startOIDC(t, fakeprovider.OIDCOptions{})
	running := start(t, withJWT(t, oidcEnvironment(issuer.IssuerURL())))
	person := newBrowser(t)

	toLogin := person.get(running.baseURL+"/auth/ui", http.Header{"X-Forwarded-Uri": {"/dashboard?tab=2"}})
	require.Equal(t, http.StatusFound, toLogin.status)
	require.Equal(t, running.baseURL+"/auth/oidc/oidc/login?return_to=%2Fdashboard%3Ftab%3D2", toLogin.location)
	person.signIn(running, "/dashboard?tab=2")
	check := person.get(running.baseURL+"/auth/ui", nil)

	require.Equal(t, http.StatusOK, check.status)
	identity := running.bearerIdentity(t, check)
	require.Equal(t, "alice-id", identity.Subject)
	require.Equal(t, "oidc", identity.Provider)
	require.Equal(t, "alice", identity.Username)
	require.Equal(t, []string{"user"}, identity.OIDCRoles)
	require.Equal(t, []string{"/staff"}, identity.Groups)
}

func TestOIDCAPICheckWithoutSessionIs401JSON(t *testing.T) {
	issuer := startOIDC(t, fakeprovider.OIDCOptions{})
	running := start(t, oidcEnvironment(issuer.IssuerURL()))

	answer := newBrowser(t).get(running.baseURL+"/auth/api", nil)

	require.Equal(t, http.StatusUnauthorized, answer.status)
	require.Equal(t, "no-store", answer.header.Get("Cache-Control"))
	require.JSONEq(t, `{"code":"unauthenticated","message":"authentication required"}`, answer.body)
}

func TestOIDCLoginNeverRedirectsToAnotherHost(t *testing.T) {
	issuer := startOIDC(t, fakeprovider.OIDCOptions{})
	running := start(t, oidcEnvironment(issuer.IssuerURL()))
	for _, returnPath := range []string{"//evil.example", "https://evil.example/", `/\evil.example`} {
		t.Run(returnPath, func(t *testing.T) {
			person := newBrowser(t)
			hop := person.get(running.baseURL+"/auth/oidc/oidc/login?return_to="+url.QueryEscape(returnPath), nil)
			for range 2 {
				require.Equal(t, http.StatusFound, hop.status, hop.body)
				hop = person.get(hop.location, nil)
			}

			require.Equal(t, http.StatusFound, hop.status, hop.body)
			require.Equal(t, running.baseURL+"/", hop.location)
		})
	}
}

func TestOIDCLogoutEndsTheSessionAtTheIssuerToo(t *testing.T) {
	issuer := startOIDC(t, fakeprovider.OIDCOptions{})
	running := start(t, oidcEnvironment(issuer.IssuerURL()))
	person := newBrowser(t)
	person.signIn(running, "/")

	toIssuer := person.get(running.baseURL+"/auth/oidc/oidc/logout", nil)

	require.Equal(t, http.StatusFound, toIssuer.status)
	require.True(t, strings.HasPrefix(toIssuer.location, issuer.IssuerURL()+"/end_session?"), toIssuer.location)
	query, err := url.ParseQuery(toIssuer.location[strings.Index(toIssuer.location, "?")+1:])
	require.NoError(t, err)
	require.Equal(t, running.baseURL+"/", query.Get("post_logout_redirect_uri"))
	backToApp := person.get(toIssuer.location, nil)
	require.Equal(t, http.StatusFound, backToApp.status)
	require.Equal(t, []string{query.Get("id_token_hint")}, issuer.IDTokenHints())
	require.Equal(t, http.StatusFound, person.get(running.baseURL+"/auth/ui", nil).status, "back to the login")
}

func TestOIDCFrontChannelLogoutWithTheSessionsIssuerAndSIDEndsIt(t *testing.T) {
	issuer := startOIDC(t, fakeprovider.OIDCOptions{})
	running := start(t, oidcEnvironment(issuer.IssuerURL()))
	person := newBrowser(t)
	person.signIn(running, "/")
	frontChannel := running.baseURL + "/auth/oidc/oidc/frontchannel-logout?" + url.Values{"iss": {issuer.IssuerURL()}}.Encode()

	otherSession := person.get(frontChannel+"&sid=another-sid", nil)
	require.Equal(t, http.StatusBadRequest, otherSession.status)
	require.Equal(t, http.StatusOK, person.get(running.baseURL+"/auth/api", nil).status, "a foreign sid ends nothing")

	logout := person.get(frontChannel+"&sid=sid-1", nil)

	require.Equal(t, http.StatusOK, logout.status)
	require.Equal(t, http.StatusUnauthorized, person.get(running.baseURL+"/auth/api", nil).status)
}

// keycloakEnvironment enriches logins through the fake's Keycloak Admin API (client credentials).
func keycloakEnvironment(issuer *fakeprovider.OIDCServer) map[string]string {
	return merged(oidcEnvironment(issuer.IssuerURL()), map[string]string{
		"KEYCLOAK_ENABLED":       "true",
		"KEYCLOAK_URL":           issuer.URL(),
		"KEYCLOAK_REALM":         "company",
		"KEYCLOAK_CLIENT_ID":     "forwardauth-admin",
		"KEYCLOAK_CLIENT_SECRET": "e2e-keycloak-secret",
	})
}

func startKeycloak(t *testing.T) *fakeprovider.OIDCServer {
	t.Helper()
	return startOIDC(t, fakeprovider.OIDCOptions{
		KeycloakRealm: "company", KeycloakClientID: "forwardauth-admin", KeycloakClientSecret: "e2e-keycloak-secret",
		User: fakeprovider.OIDCUser{
			Subject: "alice-id", PreferredUsername: "alice",
			RealmRoles: []string{"user", "app-admin"}, Groups: []string{"/staff/platform"},
			Attributes: map[string][]string{"department": {"platform"}},
		},
	})
}

func TestKeycloakEnrichmentPutsTheRealmRolesIntoTheJWT(t *testing.T) {
	issuer := startKeycloak(t)
	running := start(t, withJWT(t, keycloakEnvironment(issuer)))
	person := newBrowser(t)

	person.signIn(running, "/")
	check := person.get(running.baseURL+"/auth/api", nil)

	require.Equal(t, http.StatusOK, check.status)
	identity := running.bearerIdentity(t, check)
	require.ElementsMatch(t, []string{"user", "app-admin"}, identity.OIDCRoles)
	require.Equal(t, []string{"/staff/platform"}, identity.Groups)
	require.Positive(t, issuer.KeycloakTokenRequests())
}

func TestKeycloakRefusesALoginWithoutARequiredRealmRoleWithoutNamingIt(t *testing.T) {
	issuer := startKeycloak(t)
	running := start(t, merged(keycloakEnvironment(issuer), map[string]string{"KEYCLOAK_REQUIRED_REALM_ROLES": "superuser"}))
	person := newBrowser(t)

	hop := person.get(running.baseURL+"/auth/oidc/oidc/login", nil)
	hop = person.get(hop.location, nil)
	callback := person.get(hop.location, nil)

	require.Equal(t, http.StatusForbidden, callback.status)
	require.JSONEq(t, `{"code":"forbidden","message":"access denied"}`, callback.body)
	require.NotContains(t, callback.body, "superuser")
	require.Equal(t, http.StatusUnauthorized, person.get(running.baseURL+"/auth/api", nil).status, "no session")
	require.Eventually(t, func() bool { // the operator learns the reason from the wide event, written after the answer
		return strings.Contains(running.output.String(), `"reason":"missing realm role superuser"`)
	}, 5*time.Second, 20*time.Millisecond)
}

func TestBootFailsWhenTheIssuerIsUnreachable(t *testing.T) {
	exitCode, output := runToExit(t, merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{"EXTERNAL_URL": "http://127.0.0.1:8080"}))

	require.NotZero(t, exitCode, output)
	require.Contains(t, output, "oidc")
}
