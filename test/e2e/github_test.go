//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
)

var (
	maintainers = fakeprovider.GitHubTeam{Organization: "govengers", Slug: "maintainers"}
	admins      = fakeprovider.GitHubTeam{Organization: "govengers", Slug: "admins"}
	unrelated   = fakeprovider.GitHubTeam{Organization: "elsewhere", Slug: "crew"}
)

// gitHubEnvironment configures PROVIDER=github against fake, with JWTs.
func gitHubEnvironment(t *testing.T, fake *fakeprovider.GitHubServer) map[string]string {
	t.Helper()
	return map[string]string{
		"PROVIDER":                "github",
		"SESSION_ENCRYPTION_KEY":  testEncryptionKey,
		"SESSION_INSECURE_COOKIE": "true",
		"SHUTDOWN_DELAY_SECONDS":  "0",
		"GITHUB_CLIENT_ID":        fake.ClientID(),
		"GITHUB_CLIENT_SECRET":    fake.ClientSecret(),
		"GITHUB_AUTHORIZE_URL":    fake.AuthorizeURL(),
		"GITHUB_TOKEN_URL":        fake.TokenURL(),
		"GITHUB_API_URL":          fake.APIURL(),
		"GITHUB_ALLOWED_TEAMS":    "govengers/maintainers",
		"GITHUB_ADMIN_TEAMS":      "govengers/admins",
		"JWT_ENABLED":             "true",
		"JWT_PRIVATE_KEY":         privateKeyPEM(t),
		"JWT_AUDIENCE":            jwtAudience,
	}
}

// signIn walks a browser through the login a UI check starts: the check redirects to the login, the
// login to the provider, the provider to the callback, the callback back to returnPath on the app.
func (b *browser) signIn(running *instance, returnPath string) {
	b.t.Helper()
	hop := b.get(running.baseURL+"/auth/ui", http.Header{"X-Forwarded-Uri": {returnPath}})
	for range 3 {
		require.Equal(b.t, http.StatusFound, hop.status, hop.body)
		hop = b.get(hop.location, nil)
	}
	require.Equal(b.t, http.StatusFound, hop.status, hop.body)
	require.Equal(b.t, running.baseURL+returnPath, hop.location)
}

func TestGitHubMembersOfAnAllowedTeamGetAJWTWithTheirFilteredTeams(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{maintainers, admins, unrelated}})
	running := start(t, gitHubEnvironment(t, fake))
	person := newBrowser(t)

	toLogin := person.get(running.baseURL+"/auth/ui", http.Header{"X-Forwarded-Uri": {"/dashboard?tab=2"}})
	require.Equal(t, http.StatusFound, toLogin.status)
	require.Equal(t, running.baseURL+"/auth/github/login?return_to=%2Fdashboard%3Ftab%3D2", toLogin.location)
	person.signIn(running, "/dashboard?tab=2")
	check := person.get(running.baseURL+"/auth/ui", nil)

	require.Equal(t, http.StatusOK, check.status)
	identity := running.bearerIdentity(t, check)
	require.Equal(t, "github", identity.Provider)
	require.Equal(t, "1", identity.Subject)
	require.Equal(t, "octocat", identity.Username)
	require.ElementsMatch(t, []string{"govengers/maintainers", "govengers/admins"}, identity.Teams)
	require.Equal(t, []string{auth.RoleAdmin}, identity.Roles)
}

func TestGitHubUsersOutsideTheAllowedTeamsAreRefusedWithoutASession(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{unrelated}})
	running := start(t, gitHubEnvironment(t, fake))
	person := newBrowser(t)

	hop := person.get(running.baseURL+"/auth/github/login", nil)
	hop = person.get(hop.location, nil)
	callback := person.get(hop.location, nil)

	require.Equal(t, http.StatusForbidden, callback.status)
	require.JSONEq(t, `{"code":"forbidden","message":"access denied"}`, callback.body)
	require.Equal(t, http.StatusUnauthorized, person.get(running.baseURL+"/auth/api", nil).status)
}

func TestGitHubRefreshTeamsEndsTheSessionOfAUserRemovedFromTheAllowedTeam(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{maintainers}})
	running := start(t, gitHubEnvironment(t, fake))
	person := newBrowser(t)
	person.signIn(running, "/")
	require.Equal(t, http.StatusOK, person.do(http.MethodPost, running.baseURL+"/auth/github/refresh-teams", nil).status)

	fake.SetTeams([]fakeprovider.GitHubTeam{unrelated})
	refreshed := person.do(http.MethodPost, running.baseURL+"/auth/github/refresh-teams", nil)

	require.Equal(t, http.StatusForbidden, refreshed.status)
	require.Equal(t, http.StatusUnauthorized, person.get(running.baseURL+"/auth/api", nil).status, "the session is gone")
}

func TestTheGuardRefreshesGitHubTeamsAfterTheRefreshInterval(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{maintainers}})
	running := start(t, merged(gitHubEnvironment(t, fake), map[string]string{"SESSION_REFRESH_INTERVAL_SECONDS": "1"}))
	person := newBrowser(t)
	person.signIn(running, "/")
	require.Equal(t, http.StatusOK, person.get(running.baseURL+"/auth/api", nil).status)

	fake.SetTeams([]fakeprovider.GitHubTeam{unrelated})

	// no fake clock in a subprocess: the interval is 1 s and the check is polled
	require.Eventually(t, func() bool {
		return person.get(running.baseURL+"/auth/api", nil).status == http.StatusForbidden
	}, 10*time.Second, 100*time.Millisecond)
	require.Equal(t, http.StatusUnauthorized, person.get(running.baseURL+"/auth/api", nil).status, "the session is gone")
}

func TestGitHubLogoutRevokesTheTokenAndEndsTheSession(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{maintainers}})
	running := start(t, gitHubEnvironment(t, fake))
	person := newBrowser(t)
	person.signIn(running, "/")

	logout := person.get(running.baseURL+"/auth/github/logout", nil)

	require.Equal(t, http.StatusFound, logout.status)
	require.Equal(t, running.baseURL+"/", logout.location)
	require.Len(t, fake.RevokedTokens(), 1)
	require.Equal(t, http.StatusFound, person.get(running.baseURL+"/auth/ui", nil).status, "back to the login")
}
