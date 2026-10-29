package forwardauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	wideevent "github.com/mxcd/go-wide-event-logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/govengers/auth"
	"github.com/govengers/auth/jwt"
	"github.com/govengers/auth/session"
)

var errRedisDown = errors.New("redis down")

func TestNewServerValidatesOptions(t *testing.T) {
	guard, err := session.NewGuard(&session.GuardOptions{Store: newTestStore(t, nil)})
	require.NoError(t, err)
	valid := func() *ServerOptions {
		return &ServerOptions{
			PathPrefix: "/auth", Guard: guard, Emitter: wideevent.EmitterFunc(func(*wideevent.Event) {}),
			Logger: slog.New(slog.DiscardHandler), SampleRate: 1, MetricsRegistry: prometheus.NewRegistry(),
		}
	}
	testCases := []struct {
		name   string
		change func(options *ServerOptions)
	}{
		{name: "no guard", change: func(options *ServerOptions) { options.Guard = nil }},
		{name: "no emitter", change: func(options *ServerOptions) { options.Emitter = nil }},
		{name: "no logger", change: func(options *ServerOptions) { options.Logger = nil }},
		{name: "no metrics registry", change: func(options *ServerOptions) { options.MetricsRegistry = nil }},
		{name: "empty path prefix", change: func(options *ServerOptions) { options.PathPrefix = "" }},
		{name: "relative path prefix", change: func(options *ServerOptions) { options.PathPrefix = "auth" }},
		{name: "path prefix with trailing slash", change: func(options *ServerOptions) { options.PathPrefix = "/auth/" }},
		{name: "root path prefix", change: func(options *ServerOptions) { options.PathPrefix = "/" }},
		{name: "path prefix with a gin parameter", change: func(options *ServerOptions) { options.PathPrefix = "/auth/:tenant" }},
		{name: "path prefix with a dot-dot segment", change: func(options *ServerOptions) { options.PathPrefix = "/auth/.." }},
		{name: "negative port", change: func(options *ServerOptions) { options.Port = -1 }},
		{name: "metrics port out of range", change: func(options *ServerOptions) { options.MetricsPort = 65536 }},
		{name: "sample rate zero", change: func(options *ServerOptions) { options.SampleRate = 0 }},
		{name: "negative shutdown delay", change: func(options *ServerOptions) { options.ShutdownDelay = -time.Second }},
		{name: "shutdown delay beyond the grace period", change: func(options *ServerOptions) { options.ShutdownDelay = 11 * time.Second }},
		{name: "jwt header with a space", change: func(options *ServerOptions) { options.JWTHeader = "X Auth" }},
		{name: "jwt header the check answer sets", change: func(options *ServerOptions) { options.JWTHeader = "cache-control" }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := valid()
			testCase.change(options)

			server, err := NewServer(options)

			require.Error(t, err)
			require.Nil(t, server)
		})
	}
	t.Run("nil options", func(t *testing.T) {
		_, err := NewServer(nil)
		require.Error(t, err)
	})
	t.Run("valid options, then the same registry again", func(t *testing.T) {
		options := valid()
		_, err := NewServer(options)
		require.NoError(t, err)

		_, err = NewServer(options)

		require.ErrorContains(t, err, "register the HTTP metrics")
	})
}

func TestUICheckSendsAnAnonymousBrowserToTheAbsoluteLoginURLWithTheReturnPath(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})

	response := testHarness.serve(t, http.MethodGet, "/auth/ui", http.Header{
		"X-Forwarded-Method": {http.MethodGet}, "X-Forwarded-Host": {"app.example.com"}, "X-Forwarded-Uri": {"/dashboard?tab=2"},
	})

	require.Equal(t, http.StatusFound, response.Code)
	location, err := url.Parse(response.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, testLoginURL, location.Scheme+"://"+location.Host+location.Path)
	require.Equal(t, "/dashboard?tab=2", location.Query().Get("return_to"))
	event := testHarness.events.last(t)
	require.Equal(t, "failure", event["outcome"])
	require.Equal(t, map[string]any{"method": http.MethodGet, "host": "app.example.com", "path": "/dashboard"}, event["forward"])
	require.Equal(t, "denied", event["auth"].(map[string]any)["result"])
}

func TestAPICheckAnswers401JSONWithoutASession(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})

	response := testHarness.serve(t, http.MethodGet, "/auth/api", nil)

	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.JSONEq(t, `{"code":"unauthenticated","message":"authentication required"}`, response.Body.String())
}

func TestChecksPassASessionAndHandTheIdentityOnAsAVerifiableJWT(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{signer: newTestSigner(t)})
	cookie := testHarness.signIn(t, testIdentity())
	jwksServer := httptest.NewServer(testHarness.server.engine)
	t.Cleanup(jwksServer.Close)
	verifier, err := jwt.NewVerifier(t.Context(), &jwt.VerifierOptions{JWKSURL: jwksServer.URL + "/auth/jwks", Issuer: testIssuer})
	require.NoError(t, err)

	for _, check := range []string{"/auth/ui", "/auth/api"} {
		t.Run(check, func(t *testing.T) {
			response := testHarness.serve(t, http.MethodGet, check, nil, cookie)

			require.Equal(t, http.StatusOK, response.Code)
			require.Empty(t, response.Body.String())
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			token, found := strings.CutPrefix(response.Header().Get("Authorization"), "Bearer ")
			require.True(t, found)
			identity, err := verifier.Verify(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, "user-1", identity.Subject)
			require.Equal(t, "oidc", identity.Provider)
			require.Equal(t, []string{"admin"}, identity.Roles)
			event := testHarness.events.last(t)
			require.Equal(t, "success", event["outcome"])
			require.Equal(t, true, event["forward"].(map[string]any)["jwt_issued"])
			require.Equal(t, "user-1", event["auth"].(map[string]any)["subject"])
		})
	}
}

func TestTheJWTHeaderIsConfigurable(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{signer: newTestSigner(t), jwtHeader: "X-Identity"})
	cookie := testHarness.signIn(t, testIdentity())

	response := testHarness.serve(t, http.MethodGet, "/auth/api", nil, cookie)

	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, strings.HasPrefix(response.Header().Get("X-Identity"), "Bearer "))
	require.Empty(t, response.Header().Get("Authorization"))
}

func TestWithoutSignerChecksAnswer200WithoutTokenAndJWKSIsNotRouted(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})
	cookie := testHarness.signIn(t, testIdentity())

	check := testHarness.serve(t, http.MethodGet, "/auth/ui", nil, cookie)
	jwks := testHarness.serve(t, http.MethodGet, "/auth/jwks", nil)

	require.Equal(t, http.StatusOK, check.Code)
	require.Empty(t, check.Header().Get("Authorization"))
	require.NotContains(t, testHarness.events.last(t), "forward")
	require.Equal(t, http.StatusNotFound, jwks.Code)
	require.JSONEq(t, `{"code":"not_found","message":"not found"}`, jwks.Body.String())
}

func TestAnAPIKeyPassesTheChecksAndItsPermissionsReachTheJWT(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{signer: newTestSigner(t), apiKeys: true})
	jwksServer := httptest.NewServer(testHarness.server.engine)
	t.Cleanup(jwksServer.Close)
	verifier, err := jwt.NewVerifier(t.Context(), &jwt.VerifierOptions{JWKSURL: jwksServer.URL + "/auth/jwks", Issuer: testIssuer})
	require.NoError(t, err)
	testCases := []struct {
		name   string
		header http.Header
	}{
		{name: "X-API-Key", header: http.Header{"X-Api-Key": {testAPIKey}}},
		{name: "bearer", header: http.Header{"Authorization": {"Bearer " + testAPIKey}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			response := testHarness.serve(t, http.MethodGet, "/auth/ui", testCase.header)

			require.Equal(t, http.StatusOK, response.Code)
			identity, err := verifier.Verify(t.Context(), strings.TrimPrefix(response.Header().Get("Authorization"), "Bearer "))
			require.NoError(t, err)
			require.Equal(t, testKeyName, identity.Subject)
			require.Equal(t, []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}}, identity.Permissions)
		})
	}
	t.Run("a wrong key is refused with 401 JSON, also on the UI check", func(t *testing.T) {
		response := testHarness.serve(t, http.MethodGet, "/auth/ui", http.Header{"X-Api-Key": {"wrong-key-0123456789"}})

		require.Equal(t, http.StatusUnauthorized, response.Code)
		require.JSONEq(t, `{"code":"invalid_api_key","message":"authentication required"}`, response.Body.String())
	})
}

func TestAFailedSigningIsAnswered500AndRecorded(t *testing.T) {
	invalidPermissions := func(context.Context, string) (*auth.Identity, error) {
		return &auth.Identity{Subject: "broken", Active: true, Permissions: []auth.Permission{{Resource: "Builds", Access: auth.AccessRead}}}, nil
	}
	testHarness := newHarness(t, harnessOptions{signer: newTestSigner(t), apiKeys: true, apiKeyResolver: invalidPermissions})

	response := testHarness.serve(t, http.MethodGet, "/auth/api", http.Header{"X-Api-Key": {"resolved-key-0123456789"}})

	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.JSONEq(t, `{"code":"internal","message":"internal error"}`, response.Body.String())
	require.Empty(t, response.Header().Get("Authorization"))
	event := testHarness.events.last(t)
	require.Equal(t, "failure", event["outcome"])
	require.Contains(t, event["error"], "sign the identity token")
}

func TestTheIdentityEndpointIsMountedOnlyWhenEnabled(t *testing.T) {
	disabled := newHarness(t, harnessOptions{})
	require.Equal(t, http.StatusNotFound, disabled.serve(t, http.MethodGet, "/auth/me", nil, disabled.signIn(t, testIdentity())).Code)

	enabled := newHarness(t, harnessOptions{identityEndpoint: true})
	anonymous := enabled.serve(t, http.MethodGet, "/auth/me", nil)
	signedIn := enabled.serve(t, http.MethodGet, "/auth/me", nil, enabled.signIn(t, testIdentity()))

	require.Equal(t, http.StatusUnauthorized, anonymous.Code)
	require.Equal(t, http.StatusOK, signedIn.Code)
	var identity auth.IdentityResponse
	require.NoError(t, json.Unmarshal(signedIn.Body.Bytes(), &identity))
	require.Equal(t, "user-1", identity.Subject)
	require.Equal(t, "success", enabled.events.last(t)["outcome"])
}

func TestHealthAndReadinessAnswerWithoutWideEventsOrMetrics(t *testing.T) {
	readinessError := error(nil)
	testHarness := newHarness(t, harnessOptions{readinessCheck: func(ctx context.Context) error {
		_, hasDeadline := ctx.Deadline()
		require.True(t, hasDeadline, "the readiness check runs with a timeout")
		return readinessError
	}})

	health := testHarness.serve(t, http.MethodGet, "/auth/health", nil)
	ready := testHarness.serve(t, http.MethodGet, "/auth/ready", nil)
	readinessError = errRedisDown
	notReady := testHarness.serve(t, http.MethodGet, "/auth/ready", nil)

	require.Equal(t, http.StatusOK, health.Code)
	require.JSONEq(t, `{"status":"ok"}`, health.Body.String())
	require.Equal(t, http.StatusOK, ready.Code)
	require.Equal(t, http.StatusServiceUnavailable, notReady.Code)
	require.JSONEq(t, `{"code":"unavailable","message":"not ready"}`, notReady.Body.String())
	require.Zero(t, testHarness.events.count())
	requests, err := testutil.GatherAndCount(testHarness.registry, "forwardauth_http_requests_total")
	require.NoError(t, err)
	require.Zero(t, requests)
}

func TestMetricsLabelRouteTemplatesUnmatchedPathsAndUnknownMethods(t *testing.T) {
	item := auth.Route{Method: http.MethodGet, Path: "/auth/test/items/:id", Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})}
	testHarness := newHarness(t, harnessOptions{routes: []auth.Route{item}})

	testHarness.serve(t, http.MethodGet, "/auth/test/items/42", nil)
	testHarness.serve(t, http.MethodGet, "/auth/test/items/43", nil)
	testHarness.serve(t, http.MethodGet, "/nothing/here", nil)
	testHarness.serve(t, "BREW", "/auth/ui", nil)

	require.Equal(t, 2.0, requestCount(t, testHarness.registry, map[string]string{"route": "/auth/test/items/:id", "method": http.MethodGet, "status": "204"}))
	require.Equal(t, 1.0, requestCount(t, testHarness.registry, map[string]string{"route": "unmatched", "method": http.MethodGet, "status": "404"}))
	require.Equal(t, 1.0, requestCount(t, testHarness.registry, map[string]string{"route": "unmatched", "method": "other", "status": "404"}))
	series, err := testutil.GatherAndCount(testHarness.registry, "forwardauth_http_requests_total")
	require.NoError(t, err)
	require.Equal(t, 3, series)
	problems, err := testutil.GatherAndLint(testHarness.registry)
	require.NoError(t, err)
	require.Empty(t, problems)
}

func TestAnUnmatchedRequestIsRecordedAsAFailureAndKeptBySampling(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{sampleRate: 1000})

	response := testHarness.serve(t, http.MethodGet, "/nothing/here", nil)

	require.Equal(t, http.StatusNotFound, response.Code)
	require.Equal(t, 1, testHarness.events.count(), "failures are always kept")
	event := testHarness.events.last(t)
	require.Equal(t, "failure", event["outcome"])
	require.Equal(t, "no route", event["error"])
}

func TestATrailingSlashIsAnUnmatchedRequestNotARedirect(t *testing.T) {
	callback := auth.Route{Method: http.MethodGet, Path: testRoutePath, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusFound)
	})}
	testHarness := newHarness(t, harnessOptions{sampleRate: 1000, routes: []auth.Route{callback}})

	for _, target := range []string{"/auth/ui/", "/auth/ready/", testRoutePath + "/?code=secret-code&state=secret-state"} {
		response := testHarness.serve(t, http.MethodGet, target, nil)

		require.Equal(t, http.StatusNotFound, response.Code, target)
		require.JSONEq(t, `{"code":"not_found","message":"not found"}`, response.Body.String(), target)
		require.Empty(t, response.Header().Get("Location"), target)
	}
	require.Equal(t, 3, testHarness.events.count(), "every request has its event")
	require.Equal(t, "code=redacted&state=redacted", testHarness.events.last(t)["request"].(map[string]any)["query"])
	require.Equal(t, 3.0, requestCount(t, testHarness.registry, map[string]string{"route": "unmatched", "method": http.MethodGet, "status": "404"}))
}

// requestCount returns the forwardauth_http_requests_total sample with exactly labels, or fails.
func requestCount(t *testing.T, registry *prometheus.Registry, labels map[string]string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "forwardauth_http_requests_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			found := map[string]string{}
			for _, pair := range metric.GetLabel() {
				found[pair.GetName()] = pair.GetValue()
			}
			if maps.Equal(found, labels) {
				return metric.GetCounter().GetValue()
			}
		}
	}
	require.Failf(t, "no sample", "labels %v", labels)
	return 0
}

func TestTheWideEventCarriesARedactedQueryAndTheVersion(t *testing.T) {
	callback := auth.Route{Method: http.MethodGet, Path: testRoutePath, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusFound)
	})}
	testHarness := newHarness(t, harnessOptions{routes: []auth.Route{callback}})

	testHarness.serve(t, http.MethodGet, testRoutePath+"?code=secret-code&state=secret-state", nil)

	event := testHarness.events.last(t)
	require.Equal(t, "code=redacted&state=redacted", event["request"].(map[string]any)["query"])
	require.Equal(t, "1.2.3", event["service"].(map[string]any)["version"])
	encoded, err := json.Marshal(event)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "secret-")
}

func TestNeitherEmitterPrintsTheRawQuery(t *testing.T) {
	callback := auth.Route{Method: http.MethodGet, Path: testRoutePath, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusFound)
	})}
	testCases := []struct {
		name       string
		newEmitter func(writer io.Writer) wideevent.Emitter
	}{
		{name: "dev", newEmitter: func(writer io.Writer) wideevent.Emitter { return wideevent.DevWriterEmitter(writer) }},
		{name: "json", newEmitter: wideevent.JSONWriterEmitter},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			output := &bytes.Buffer{}
			testHarness := newHarness(t, harnessOptions{routes: []auth.Route{callback}, emitter: testCase.newEmitter(output)})

			testHarness.serve(t, http.MethodGet, testRoutePath+"?code=secret-code&state=secret-state", nil)

			require.Contains(t, output.String(), "code=redacted&state=redacted")
			require.NotContains(t, output.String(), "secret-")
		})
	}
}

func TestTheSamplerKeepsFailuresRefusalsAndDegradedEvents(t *testing.T) {
	keepEveryThousandth := sampler(1000)
	testCases := []struct {
		name   string
		record func(we *wideevent.Event)
		kept   bool
	}{
		{name: "failure", record: func(we *wideevent.Event) { we.Failure(errRedisDown) }, kept: true},
		{name: "server error", record: func(we *wideevent.Event) { we.Int("response.status", http.StatusBadGateway) }, kept: true},
		{name: "401", record: func(we *wideevent.Event) { we.Int("response.status", http.StatusUnauthorized) }, kept: true},
		{name: "403", record: func(we *wideevent.Event) { we.Int("response.status", http.StatusForbidden) }, kept: true},
		{name: "degraded success", record: func(we *wideevent.Event) { we.Success().Bool("degraded", true) }, kept: true},
		{name: "plain success", record: func(we *wideevent.Event) { we.Success().Int("response.status", http.StatusOK) }, kept: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			we := wideevent.Begin(nil, "test")
			testCase.record(we)

			require.Equal(t, testCase.kept, keepEveryThousandth.ShouldSample(we))
		})
	}
}

func TestTheObserverRecordsOutcomesOnTheWideEventAndCountsThem(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})

	testHarness.serve(t, http.MethodGet, "/auth/api", nil)
	testHarness.serve(t, http.MethodGet, "/auth/api", nil, testHarness.signIn(t, testIdentity()))

	event := testHarness.events.last(t)
	require.Equal(t, map[string]any{"provider": "oidc", "action": "authenticate", "result": "success", "subject": "user-1"}, event["auth"])
	outcomes, err := testutil.GatherAndCount(testHarness.registry, "forwardauth_auth_outcomes_total")
	require.NoError(t, err)
	require.Equal(t, 2, outcomes, "one series for the denied and one for the successful authentication")
}

func TestAPanicIsAnswered500AndRecordedWithItsStack(t *testing.T) {
	panicking := auth.Route{Method: http.MethodGet, Path: testRoutePath, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})}
	testHarness := newHarness(t, harnessOptions{routes: []auth.Route{panicking}})

	response := testHarness.serve(t, http.MethodGet, testRoutePath, nil)

	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.JSONEq(t, `{"code":"internal","message":"internal error"}`, response.Body.String())
	event := testHarness.events.last(t)
	require.Equal(t, "panic: boom", event["error"])
	require.Contains(t, event["panic"].(map[string]any)["stack"], "runtime/debug.Stack")
	require.Equal(t, 1.0, requestCount(t, testHarness.registry, map[string]string{"route": testRoutePath, "method": http.MethodGet, "status": "500"}))
}

func TestRunAnswersNotReadyDuringTheShutdownDelayThenDrains(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})
	delayStarted := make(chan time.Duration, 1)
	releaseDelay := make(chan struct{})
	testHarness.server.delay = func(duration time.Duration) {
		delayStarted <- duration
		<-releaseDelay
	}
	testHarness.server.options.ShutdownDelay = 5 * time.Second
	ctx, stop := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- testHarness.server.Run(ctx) }()
	require.Equal(t, http.StatusOK, testHarness.serve(t, http.MethodGet, "/auth/ready", nil).Code)

	stop()

	require.Equal(t, 5*time.Second, <-delayStarted)
	require.Equal(t, http.StatusServiceUnavailable, testHarness.serve(t, http.MethodGet, "/auth/ready", nil).Code)
	require.Equal(t, http.StatusOK, testHarness.serve(t, http.MethodGet, "/auth/health", nil).Code, "liveness stays up")
	close(releaseDelay)
	require.NoError(t, <-runResult)
}

func TestRunReturnsTheErrorOfAListenerThatCannotStart(t *testing.T) {
	occupied, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", ":0") // every interface, as the server binds it
	require.NoError(t, err)
	t.Cleanup(func() { _ = occupied.Close() }) // test listener, nothing to flush
	testHarness := newHarness(t, harnessOptions{})
	testHarness.server.metricsServer.Addr = occupied.Addr().String()

	err = testHarness.server.Run(t.Context())

	require.ErrorContains(t, err, "serve:")
}

func TestTheMetricsListenerServesOnlyGETMetrics(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})
	serveMetrics := func(method, target string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		testHarness.server.metricsServer.Handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), method, target, nil))
		return recorder
	}

	metrics := serveMetrics(http.MethodGet, "/metrics")

	require.Equal(t, http.StatusOK, metrics.Code)
	require.Contains(t, metrics.Body.String(), "forwardauth_http_requests_in_flight")
	require.Equal(t, http.StatusNotFound, serveMetrics(http.MethodGet, "/").Code)
	require.Equal(t, http.StatusMethodNotAllowed, serveMetrics(http.MethodPost, "/metrics").Code)
}

func TestBothListenersBoundEveryPhaseOfAConnection(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})

	for _, server := range []*http.Server{testHarness.server.httpServer, testHarness.server.metricsServer} {
		require.Positive(t, server.ReadHeaderTimeout, server.Addr)
		require.Positive(t, server.ReadTimeout, server.Addr)
		require.Positive(t, server.WriteTimeout, server.Addr)
		require.Positive(t, server.IdleTimeout, server.Addr)
	}
}

func TestNetHTTPErrorLinesOfBothListenersAreJSONThroughTheLogger(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})

	testHarness.server.httpServer.ErrorLog.Print("http: Accept error: public")
	testHarness.server.metricsServer.ErrorLog.Print("http: Accept error: metrics")

	lines := strings.Split(strings.TrimSpace(testHarness.logs.String()), "\n")
	require.Len(t, lines, 2)
	for index, listener := range []string{"public", "metrics"} {
		var line map[string]any
		require.NoError(t, json.Unmarshal([]byte(lines[index]), &line))
		require.Equal(t, "ERROR", line["level"])
		require.Equal(t, "http: Accept error: "+listener, line["msg"])
	}
}

func TestNewHTTPMetricsRequiresARegisterer(t *testing.T) {
	for _, options := range []*httpMetricsOptions{nil, {pathPrefix: "/auth"}} {
		metrics, err := newHTTPMetrics(options)

		require.ErrorContains(t, err, "a registerer is required")
		require.Nil(t, metrics)
	}
}

func TestMethodLabelBoundsTheMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace} {
		require.Equal(t, method, methodLabel(method))
	}
	require.Equal(t, "other", methodLabel("get"))
	require.Equal(t, "other", methodLabel("PROPFIND"))
}

// TestMain fails the package when a test leaves a goroutine behind, such as a listener of Run [TST-009].
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	goleak.VerifyTestMain(m)
}
