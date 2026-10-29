//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeprovider"
)

func TestTheIdentityEndpointIsMountedOnlyWhenEnabled(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{maintainers}})
	disabled := start(t, gitHubEnvironment(t, fake))
	enabled := start(t, merged(gitHubEnvironment(t, fake), map[string]string{"IDENTITY_ENDPOINT_ENABLED": "true"}))
	person := newBrowser(t)

	require.Equal(t, http.StatusNotFound, person.get(disabled.baseURL+"/auth/me", nil).status)
	require.Equal(t, http.StatusUnauthorized, person.get(enabled.baseURL+"/auth/me", nil).status)
	person.signIn(enabled, "/")
	identityAnswer := person.get(enabled.baseURL+"/auth/me", nil)

	require.Equal(t, http.StatusOK, identityAnswer.status)
	var identity struct {
		Provider string `json:"provider"`
		Username string `json:"username"`
	}
	require.NoError(t, json.Unmarshal([]byte(identityAnswer.body), &identity))
	require.Equal(t, "github", identity.Provider)
	require.Equal(t, "octocat", identity.Username)
}

func TestReadinessFailsDuringTheShutdownDelayWhileTheProcessStillServes(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{})
	running := start(t, merged(gitHubEnvironment(t, fake), map[string]string{"SHUTDOWN_DELAY_SECONDS": "1"}))
	client := newBrowser(t)
	require.Equal(t, http.StatusOK, client.get(running.baseURL+"/auth/ready", nil).status)

	running.stop(t)

	require.Eventually(t, func() bool {
		return client.get(running.baseURL+"/auth/ready", nil).status == http.StatusServiceUnavailable
	}, 900*time.Millisecond, 20*time.Millisecond)
	require.Equal(t, http.StatusOK, client.get(running.baseURL+"/auth/health", nil).status, "liveness stays up while draining")
	select {
	case <-running.exited:
	case <-time.After(stopTimeout):
		require.FailNow(t, "forwardauth did not exit after the shutdown delay")
	}
	require.True(t, running.command.ProcessState.Success(), running.output.String())
}

func TestTheMetricsPortServesRequestAndOutcomeMetrics(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{})
	running := start(t, gitHubEnvironment(t, fake))
	client := newBrowser(t)
	require.Equal(t, http.StatusUnauthorized, client.get(running.baseURL+"/auth/api", nil).status)

	metrics := client.get(running.metricsURL+"/metrics", nil)

	require.Equal(t, http.StatusOK, metrics.status)
	require.Contains(t, metrics.body, `forwardauth_http_requests_total{method="GET",route="/auth/api",status="401"} 1`)
	require.Contains(t, metrics.body, `forwardauth_auth_outcomes_total{action="authenticate",provider="session",result="denied"} 1`)
	require.Contains(t, metrics.body, "go_goroutines")
	require.Contains(t, metrics.body, "go_build_info")
	require.Equal(t, http.StatusNotFound, client.get(running.baseURL+"/metrics", nil).status, "metrics never on the public port")
	require.Equal(t, http.StatusNotFound, client.get(running.metricsURL+"/", nil).status, "only /metrics on the metrics port")
}

func TestTheWideEventsAreJSONLinesWithoutSecrets(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{Teams: []fakeprovider.GitHubTeam{maintainers}})
	running := start(t, merged(gitHubEnvironment(t, fake), map[string]string{"WIDE_EVENT_SAMPLE_RATE": "1"}))
	person := newBrowser(t)

	person.signIn(running, "/")

	output := running.output.String()
	require.Contains(t, output, `"auth":{`)
	require.Contains(t, output, `"query":"code=redacted&state=redacted"`)
	require.NotContains(t, output, fake.ClientSecret())
	require.NotContains(t, output, "octocat@example.com", "no emails in the events")
	require.Contains(t, output, `"http":{"github":{"calls":`, "the callback's event sums its GitHub calls")
	require.Contains(t, person.get(running.metricsURL+"/metrics", nil).body, `forwardauth_dependency_request_duration_seconds_count{dependency="github",operation="POST",outcome="success"}`)
}

func TestTheDevEmitterPrintsNoQueryValues(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{})
	running := start(t, merged(gitHubEnvironment(t, fake), map[string]string{"DEV_MODE": "true", "WIDE_EVENT_SAMPLE_RATE": "1"}))

	refused := newBrowser(t).get(running.baseURL+"/auth/github/callback?code=dev-mode-code&state=dev-mode-state", nil)

	require.GreaterOrEqual(t, refused.status, http.StatusBadRequest)
	require.Eventually(t, func() bool { return strings.Contains(running.output.String(), "code=redacted&state=redacted") }, 5*time.Second, 20*time.Millisecond)
	require.NotContains(t, running.output.String(), "dev-mode-")
}
