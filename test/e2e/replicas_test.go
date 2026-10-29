//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeprovider"
)

func TestTwoReplicasShareSessionsThroughRedis(t *testing.T) {
	redisServer := miniredis.RunT(t)
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{maintainers}})
	shared := merged(gitHubEnvironment(t, fake), map[string]string{"SESSION_REDIS_ENABLED": "true", "SESSION_REDIS_ADDRESS": redisServer.Addr()})
	replicaA, replicaB := start(t, shared), start(t, shared)
	person := newBrowser(t)

	person.signIn(replicaA, "/")
	require.Equal(t, http.StatusOK, person.get(replicaB.baseURL+"/auth/ui", nil).status, "B knows A's session")

	require.Equal(t, http.StatusFound, person.get(replicaB.baseURL+"/auth/github/logout", nil).status)
	require.Equal(t, http.StatusUnauthorized, person.get(replicaA.baseURL+"/auth/api", nil).status, "A knows B's logout")

	require.Equal(t, http.StatusOK, person.get(replicaA.baseURL+"/auth/ready", nil).status)
	redisServer.Close()
	require.Equal(t, http.StatusServiceUnavailable, person.get(replicaA.baseURL+"/auth/ready", nil).status, "not ready without Redis")
}
