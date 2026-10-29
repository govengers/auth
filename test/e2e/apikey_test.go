//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
)

func TestAPIKeysPassTheChecksAndCarryTheirConfiguredPermissionsInTheJWT(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{})
	running := start(t, merged(gitHubEnvironment(t, fake), map[string]string{
		"API_KEYS":            "ci:ci-secret-0123456789,reader:reader-secret-0123456789",
		"API_KEY_PERMISSIONS": "ci=builds:write+*:read",
	}))
	client := newBrowser(t)
	testCases := []struct {
		name   string
		check  string
		header http.Header
	}{
		{name: "X-API-Key on the API check", check: "/auth/api", header: http.Header{"X-Api-Key": {"ci-secret-0123456789"}}},
		{name: "bearer on the UI check", check: "/auth/ui", header: http.Header{"Authorization": {"Bearer ci-secret-0123456789"}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			answer := client.get(running.baseURL+testCase.check, testCase.header)

			require.Equal(t, http.StatusOK, answer.status, answer.body)
			identity := running.bearerIdentity(t, answer)
			require.Equal(t, "apikey", identity.Provider)
			require.Equal(t, "ci", identity.Subject)
			require.Equal(t, []any{"builds:write", "*:read"}, identity.Claims["permissions"])
			require.Equal(t, []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}, {Resource: auth.AllResources, Access: auth.AccessRead}}, identity.Permissions)
		})
	}
	t.Run("a key without a permissions entry has no permissions claim", func(t *testing.T) {
		answer := client.get(running.baseURL+"/auth/api", http.Header{"X-Api-Key": {"reader-secret-0123456789"}})

		require.Equal(t, http.StatusOK, answer.status)
		identity := running.bearerIdentity(t, answer)
		require.Equal(t, "reader", identity.Subject)
		require.NotContains(t, identity.Claims, "permissions")
		require.Empty(t, identity.Permissions)
	})
	t.Run("a wrong key is refused", func(t *testing.T) {
		answer := client.get(running.baseURL+"/auth/ui", http.Header{"X-Api-Key": {"wrong-secret-0123456789"}})

		require.Equal(t, http.StatusUnauthorized, answer.status)
		require.JSONEq(t, `{"code":"invalid_api_key","message":"authentication required"}`, answer.body)
		require.NotContains(t, running.output.String(), "secret-0123456789", "keys never reach the log")
	})
}
