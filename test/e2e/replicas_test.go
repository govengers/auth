//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeprovider"
)

func TestTwoReplicasShareSessionsThroughRedis(t *testing.T) {
	redisServer := miniredis.RunT(t)
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{maintainers}})
	shared := merged(gitHubEnvironment(t, fake), map[string]string{"SESSION_REDIS_ENABLED": "true", "SESSION_REDIS_ADDRESS": redisServer.Addr(), "WIDE_EVENT_SAMPLE_RATE": "1"})
	replicaA, replicaB := start(t, shared), start(t, shared)
	person := newBrowser(t)

	person.signIn(replicaA, "/")
	require.Equal(t, http.StatusOK, person.get(replicaB.baseURL+"/auth/ui", nil).status, "B knows A's session")
	require.Eventually(t, func() bool {
		return strings.Contains(replicaB.output.String(), `"cache":{"backend":"redis","calls":`)
	}, 5*time.Second, 20*time.Millisecond, "the check's event sums its Redis calls")

	sessionCookie := cookieHeader(t, person, replicaA.baseURL)
	require.Equal(t, http.StatusOK, newBrowser(t).get(replicaA.baseURL+"/auth/api", sessionCookie).status, "the replayed cookie authenticates")
	require.Equal(t, http.StatusFound, person.get(replicaB.baseURL+"/auth/github/logout", nil).status)
	require.Equal(t, http.StatusUnauthorized, newBrowser(t).get(replicaA.baseURL+"/auth/api", sessionCookie).status, "A knows B's logout, also for a kept cookie")

	require.Equal(t, http.StatusOK, person.get(replicaA.baseURL+"/auth/ready", nil).status)
	redisServer.Close()
	require.Equal(t, http.StatusServiceUnavailable, person.get(replicaA.baseURL+"/auth/ready", nil).status, "not ready without Redis")
}

// cookieHeader returns the Cookie header person's jar sends to target, so a test can replay it after the
// jar dropped the cookie.
func cookieHeader(t *testing.T, person *browser, target string) http.Header {
	t.Helper()
	parsed, err := url.Parse(target)
	require.NoError(t, err)
	var pairs []string
	for _, cookie := range person.client.Jar.Cookies(parsed) {
		pairs = append(pairs, cookie.String())
	}
	require.NotEmpty(t, pairs, "no cookie for %s", target)
	return http.Header{"Cookie": {strings.Join(pairs, "; ")}}
}
