package forwardauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	wideevent "github.com/mxcd/go-wide-event-logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

func newTestDependencies(t *testing.T) (*Dependencies, *prometheus.Registry) {
	t.Helper()
	registry := prometheus.NewRegistry()
	dependencies, err := NewDependencies(&DependenciesOptions{Registerer: registry})
	require.NoError(t, err)
	return dependencies, registry
}

// dependencyCount returns how many calls forwardauth_dependency_request_duration_seconds observed with labels.
func dependencyCount(t *testing.T, registry *prometheus.Registry, dependency, operation, outcome string) uint64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	want := map[string]string{"dependency": dependency, "operation": operation, "outcome": outcome}
	for _, family := range families {
		if family.GetName() != "forwardauth_dependency_request_duration_seconds" {
			continue
		}
		for _, metric := range family.GetMetric() {
			found := map[string]string{}
			for _, pair := range metric.GetLabel() {
				found[pair.GetName()] = pair.GetValue()
			}
			if found["dependency"] == want["dependency"] && found["operation"] == want["operation"] && found["outcome"] == want["outcome"] {
				return metric.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

func TestNewDependenciesValidatesOptions(t *testing.T) {
	_, err := NewDependencies(nil)
	require.Error(t, err)
	_, err = NewDependencies(&DependenciesOptions{})
	require.Error(t, err)
	registry := prometheus.NewRegistry()
	_, err = NewDependencies(&DependenciesOptions{Registerer: registry})
	require.NoError(t, err)

	_, err = NewDependencies(&DependenciesOptions{Registerer: registry})

	require.ErrorContains(t, err, "register the dependency metrics")
}

func TestACheckRecordsItsSessionStoreCallsOnTheEventAndInTheHistogram(t *testing.T) {
	dependencies, registry := newTestDependencies(t)
	testHarness := newHarness(t, harnessOptions{dependencies: dependencies})
	cookie := testHarness.signIn(t, testIdentity())
	before := dependencyCount(t, registry, "redis", "get", "success")

	response := testHarness.serve(t, http.MethodGet, "/auth/api", nil, cookie)

	require.Equal(t, http.StatusOK, response.Code)
	cache := testHarness.events.last(t)["cache"].(map[string]any)
	require.Equal(t, "redis", cache["backend"])
	require.Positive(t, cache["calls"])
	require.Equal(t, 0, cache["failures"])
	require.IsType(t, time.Duration(0), cache["duration_ms"])
	require.NotContains(t, cache, "error")
	require.Greater(t, dependencyCount(t, registry, "redis", "get", "success"), before)
}

func TestHTTPCallsOfARequestAreSummedOnItsEvent(t *testing.T) {
	dependencies, registry := newTestDependencies(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/down" {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(upstream.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	client := dependencies.HTTPClient("github")
	call := func(ctx context.Context, target string) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		require.NoError(t, err)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close() // the status is all the test needs
		}
	}
	teams := auth.Route{Method: http.MethodGet, Path: testRoutePath, Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call(request.Context(), upstream.URL+"/ok")
		call(request.Context(), upstream.URL+"/down")
		call(request.Context(), closed.URL+"/teams?login=alice@example.com")
		writer.WriteHeader(http.StatusNoContent)
	})}
	testHarness := newHarness(t, harnessOptions{routes: []auth.Route{teams}})

	testHarness.serve(t, http.MethodGet, testRoutePath, nil)
	call(t.Context(), upstream.URL+"/outside-a-request")

	github := testHarness.events.last(t)["http"].(map[string]any)["github"].(map[string]any)
	require.Equal(t, 3, github["calls"])
	require.Equal(t, 2, github["failures"])
	require.Equal(t, http.StatusServiceUnavailable, github["status"], "the latest response")
	require.Contains(t, github["error"], "connect")
	require.NotContains(t, github["error"], "alice", "no URL in the recorded error")
	require.Equal(t, uint64(2), dependencyCount(t, registry, "github", http.MethodGet, "success"), "/ok and the call outside a request")
	require.Equal(t, uint64(2), dependencyCount(t, registry, "github", http.MethodGet, "failure"))
}

// failingBackend fails every operation.
type failingBackend struct{}

func (failingBackend) Put(context.Context, string, string, []byte, time.Duration) error {
	return errRedisDown
}

func (failingBackend) Get(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, errRedisDown
}

func (failingBackend) Pop(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, errRedisDown
}

func (failingBackend) Revoke(context.Context, string, time.Duration) error { return errRedisDown }

func TestSessionStoreFailuresAreRecordedButARevokedSessionIsNot(t *testing.T) {
	dependencies, registry := newTestDependencies(t)
	calls := &dependencyCalls{sums: map[string]*dependencySum{}}
	ctx := context.WithValue(t.Context(), dependencyCallsKey{}, calls)
	failing := dependencies.Backend(failingBackend{})

	require.ErrorIs(t, failing.Put(ctx, "session", "key", nil, time.Minute), errRedisDown)
	_, _, err := failing.Get(ctx, "session", "key")
	require.ErrorIs(t, err, errRedisDown)
	_, _, err = failing.Pop(ctx, "session", "key")
	require.ErrorIs(t, err, errRedisDown)
	require.ErrorIs(t, failing.Revoke(ctx, "session", time.Minute), errRedisDown)
	we := wideevent.Begin(nil, "test")
	calls.recordOn(we)

	cache := we.FieldsMap()["cache"].(map[string]any)
	require.Equal(t, 4, cache["failures"])
	require.Equal(t, "redis down", cache["error"])
	for _, operation := range []string{"put", "get", "pop", "revoke"} {
		require.Equal(t, uint64(1), dependencyCount(t, registry, "redis", operation, "failure"), operation)
	}

	memory, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	revoking := dependencies.Backend(memory)
	require.NoError(t, revoking.Revoke(ctx, "revoked", time.Minute))
	require.ErrorIs(t, revoking.Put(ctx, "revoked", "key", nil, time.Minute), session.ErrSessionRevoked)
	require.Equal(t, uint64(1), dependencyCount(t, registry, "redis", "put", "success"), "a revoked session is an answer")
}
