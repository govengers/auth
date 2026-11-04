package forwardauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

const (
	callerTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	callerSpanID  = "00f067aa0ba902b7"
)

// A check continues Traefik's trace: one server span per request, its IDs on the wide event; the
// probes make no span [TRC].
func TestAChecksSpanContinuesTheCallersTraceAndReachesTheWideEvent(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	testHarness := newHarness(t, harnessOptions{tracerProvider: sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))})

	testHarness.serve(t, http.MethodGet, "/auth/api", http.Header{"Traceparent": {"00-" + callerTraceID + "-" + callerSpanID + "-01"}})
	event := testHarness.events.last(t)
	testHarness.serve(t, http.MethodGet, "/auth/health", nil)
	testHarness.serve(t, http.MethodGet, "/auth/ready", nil)

	spans := recorder.Ended()
	require.Len(t, spans, 1, "health and readiness make no span")
	require.Equal(t, "GET /auth/api", spans[0].Name())
	require.Equal(t, trace.SpanKindServer, spans[0].SpanKind())
	require.Equal(t, callerTraceID, spans[0].SpanContext().TraceID().String())
	require.Equal(t, callerSpanID, spans[0].Parent().SpanID().String())
	traceFields, isMap := event["trace"].(map[string]any)
	require.True(t, isMap, "event %v", event)
	require.Equal(t, callerTraceID, traceFields["id"])
	require.Equal(t, spans[0].SpanContext().SpanID().String(), traceFields["span_id"])
}

func TestWithoutATracerProviderTheEventCarriesNoTrace(t *testing.T) {
	testHarness := newHarness(t, harnessOptions{})

	testHarness.serve(t, http.MethodGet, "/auth/api", nil)

	require.NotContains(t, testHarness.events.last(t), "trace")
}

// The provider's calls are client spans that send the trace context on [TRC].
func TestOutboundCallsAreTracedAndCarryTheTraceContext(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	dependencies, err := NewDependencies(&DependenciesOptions{Registerer: prometheus.NewRegistry(), TracerProvider: provider})
	require.NoError(t, err)
	var traceparent string
	issuer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		traceparent = request.Header.Get("Traceparent")
		writer.WriteHeader(http.StatusOK)
	}))
	defer issuer.Close()
	ctx, parent := provider.Tracer("test").Start(t.Context(), "GET /auth/oidc/main/callback")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer.URL+"/token", nil)
	require.NoError(t, err)

	response, err := dependencies.HTTPClient("oidc").Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	parent.End()

	spans := recorder.Ended()
	require.Len(t, spans, 2)
	require.Equal(t, trace.SpanKindClient, spans[0].SpanKind())
	require.Equal(t, parent.SpanContext().SpanID(), spans[0].Parent().SpanID())
	require.Equal(t, "00-"+parent.SpanContext().TraceID().String()+"-"+spans[0].SpanContext().SpanID().String()+"-01", traceparent)
}

func TestTraceRedisInstrumentsTheClient(t *testing.T) {
	dependencies, err := NewDependencies(&DependenciesOptions{Registerer: prometheus.NewRegistry()})
	require.NoError(t, err)
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { require.NoError(t, client.Close()) }()

	require.NoError(t, dependencies.TraceRedis(client))
	require.Error(t, dependencies.TraceRedis(unsupportedRedisClient{client}), "a client type redisotel does not know")
}

// unsupportedRedisClient hides the concrete client type from redisotel.
type unsupportedRedisClient struct{ redis.UniversalClient }
