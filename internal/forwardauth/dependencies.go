package forwardauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	wideevent "github.com/mxcd/go-wide-event-logger"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/govengers/auth/session"
)

const (
	defaultHTTPTimeout = 10 * time.Second // the library's default for outbound HTTP (design 1.2)
	redisDependency    = "redis"
	redisNamespace     = "cache"
)

// Dependencies records the outbound calls of the binary, the Redis session operations and the HTTP calls
// of the provider and Keycloak, in forwardauth_dependency_request_duration_seconds and, during a request,
// summed per dependency on its wide event [LOG-004, LOG-006, MET-006]. Calls outside a request (discovery
// at boot, JWKS refreshes) reach only the metric. It is safe for concurrent use.
type Dependencies struct {
	durations *prometheus.HistogramVec
}

// DependenciesOptions configure Dependencies.
type DependenciesOptions struct {
	Registerer prometheus.Registerer // required: the registry /metrics serves [MET-002]
}

// NewDependencies registers the dependency histogram on options.Registerer.
func NewDependencies(options *DependenciesOptions) (*Dependencies, error) {
	if options == nil || options.Registerer == nil {
		return nil, errors.New("forwardauth dependencies: Registerer is required")
	}
	durations := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace, Subsystem: "dependency", Name: "request_duration_seconds",
		Help: "Outbound call duration by dependency, operation and outcome.", Buckets: prometheus.DefBuckets,
	}, []string{"dependency", "operation", "outcome"})
	if err := options.Registerer.Register(durations); err != nil {
		return nil, fmt.Errorf("register the dependency metrics: %w", err)
	}
	return &Dependencies{durations: durations}, nil
}

// HTTPClient returns a client with the 10 s default timeout whose calls are recorded as dependency name
// (operation: the method), under http.<name> on the wide event. A transport error or a 5xx is a failure;
// the recorded error is the transport's reduced by transportFailure: no URL, whose query may carry
// personal data, and no byte of a malformed answer [LOG-009]. The caller gets the error unchanged.
func (d *Dependencies) HTTPClient(name string) *http.Client {
	return &http.Client{Timeout: defaultHTTPTimeout, Transport: &recordingTransport{dependencies: d, name: name}}
}

// Backend wraps backend so its operations are recorded as dependency "redis" (operation: put, get, pop,
// compare_and_swap, revoke), under cache on the wide event. ErrSessionRevoked is an answer, not a failure.
func (d *Dependencies) Backend(backend session.Backend) session.Backend {
	return &recordingBackend{dependencies: d, backend: backend}
}

// dependencyCall is one finished outbound call.
type dependencyCall struct {
	dependency, operation string
	namespace             string // of the wide-event fields
	backend               string // cache.backend; empty for HTTP
	duration              time.Duration
	status                int   // HTTP status; 0 for Redis or without a response
	failed                bool  // a failure, also without an error (a 5xx)
	err                   error // the failure's error, safe to record
}

func (d *Dependencies) record(ctx context.Context, call dependencyCall) {
	outcome := "success"
	if call.failed {
		outcome = "failure"
	}
	d.durations.WithLabelValues(call.dependency, call.operation, outcome).Observe(call.duration.Seconds())
	if calls, found := ctx.Value(dependencyCallsKey{}).(*dependencyCalls); found {
		calls.add(call)
	}
}

type recordingTransport struct {
	dependencies *Dependencies
	name         string
}

func (t *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	start := time.Now()
	response, err := http.DefaultTransport.RoundTrip(request)
	call := dependencyCall{
		dependency: t.name, operation: methodLabel(request.Method), namespace: "http." + t.name,
		duration: time.Since(start), failed: err != nil,
	}
	if err != nil {
		call.err = transportFailure(err)
	}
	if response != nil {
		call.status = response.StatusCode
		call.failed = call.failed || response.StatusCode >= http.StatusInternalServerError
	}
	t.dependencies.record(request.Context(), call)
	return response, err
}

// transportFailure reduces a transport error to what is safe to record: the text of a malformed answer
// repeats the server's bytes (a header line, a status line), which may be personal data [LOG-009]. A
// cancelled or expired context and a dial error are kept; anything else is named by the type of its
// innermost error.
func transportFailure(err error) error {
	var dialError *net.OpError
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.As(err, &dialError) && dialError.Op == "dial":
		return dialError
	}
	for errors.Unwrap(err) != nil {
		err = errors.Unwrap(err)
	}
	return fmt.Errorf("transport failure (%T)", err)
}

type recordingBackend struct {
	dependencies *Dependencies
	backend      session.Backend
}

func (b *recordingBackend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	start := time.Now()
	err := b.backend.Put(ctx, sessionID, key, value, ttl)
	b.record(ctx, "put", start, err)
	return err
}

func (b *recordingBackend) Get(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	start := time.Now()
	value, found, err := b.backend.Get(ctx, sessionID, key)
	b.record(ctx, "get", start, err)
	return value, found, err
}

func (b *recordingBackend) Pop(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	start := time.Now()
	value, found, err := b.backend.Pop(ctx, sessionID, key)
	b.record(ctx, "pop", start, err)
	return value, found, err
}

func (b *recordingBackend) CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (bool, error) {
	start := time.Now()
	swapped, err := b.backend.CompareAndSwap(ctx, sessionID, key, previous, value)
	b.record(ctx, "compare_and_swap", start, err)
	return swapped, err
}

func (b *recordingBackend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	start := time.Now()
	err := b.backend.Revoke(ctx, sessionID, ttl)
	b.record(ctx, "revoke", start, err)
	return err
}

func (b *recordingBackend) record(ctx context.Context, operation string, start time.Time, err error) {
	if errors.Is(err, session.ErrSessionRevoked) {
		err = nil
	}
	b.dependencies.record(ctx, dependencyCall{
		dependency: redisDependency, operation: operation, namespace: redisNamespace, backend: redisDependency,
		duration: time.Since(start), failed: err != nil, err: err,
	})
}

// dependencyCallsKey is the context key of a request's *dependencyCalls.
type dependencyCallsKey struct{}

// dependencyCalls sums the outbound calls of one request per wide-event namespace, so a loop of calls
// (GitHub team pages) adds a handful of fields, not a handful per call [LOG-006].
type dependencyCalls struct {
	mutex sync.Mutex
	sums  map[string]*dependencySum
}

type dependencySum struct {
	backend                 string
	calls, failures, status int // status: of the latest HTTP response
	duration                time.Duration
	firstError              error
}

func (c *dependencyCalls) add(call dependencyCall) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	sum, found := c.sums[call.namespace]
	if !found {
		sum = &dependencySum{backend: call.backend}
		c.sums[call.namespace] = sum
	}
	sum.calls++
	sum.duration += call.duration
	if call.status != 0 {
		sum.status = call.status
	}
	if call.failed {
		sum.failures++
	}
	if sum.firstError == nil {
		sum.firstError = call.err
	}
}

// recordOn writes <namespace>.calls, .failures, .duration_ms and, when set, .backend, .status and .error.
func (c *dependencyCalls) recordOn(we *wideevent.Event) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for namespace, sum := range c.sums {
		we.Int(namespace+".calls", sum.calls).Int(namespace+".failures", sum.failures).Dur(namespace+".duration_ms", sum.duration)
		if sum.backend != "" {
			we.Str(namespace+".backend", sum.backend)
		}
		if sum.status != 0 {
			we.Int(namespace+".status", sum.status)
		}
		if sum.firstError != nil {
			we.Err(namespace+".error", sum.firstError)
		}
	}
}

// recordDependencies collects the request's outbound calls and writes their sums on its wide event.
func recordDependencies(ginContext *gin.Context) {
	calls := &dependencyCalls{sums: map[string]*dependencySum{}}
	ginContext.Request = ginContext.Request.WithContext(context.WithValue(ginContext.Request.Context(), dependencyCallsKey{}, calls))
	ginContext.Next()
	if we := wideevent.FromGin(ginContext); we != nil {
		calls.recordOn(we)
	}
}
