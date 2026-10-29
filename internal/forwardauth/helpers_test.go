package forwardauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	wideevent "github.com/mxcd/go-wide-event-logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/jwt"
	"github.com/govengers/auth/prometheusadapter"
	"github.com/govengers/auth/session"
)

const (
	testLoginURL  = "https://app.example.com/auth/test/login"
	testIssuer    = "https://app.example.com"
	testAPIKey    = "ci-secret-0123456789"
	testKeyName   = "ci"
	testRoutePath = "/auth/test/callback"
)

// eventRecorder collects the emitted wide events; servers emit from their own goroutines.
type eventRecorder struct {
	mutex  sync.Mutex
	events []*wideevent.Event
}

func (r *eventRecorder) emit(we *wideevent.Event) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.events = append(r.events, we)
}

func (r *eventRecorder) count() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return len(r.events)
}

// last returns the fields of the last emitted event.
func (r *eventRecorder) last(t *testing.T) map[string]any {
	t.Helper()
	r.mutex.Lock()
	defer r.mutex.Unlock()
	require.NotEmpty(t, r.events, "no wide event was emitted")
	return r.events[len(r.events)-1].FieldsMap()
}

// harness is a Server on a memory session store with every optional part configurable.
type harness struct {
	server   *Server
	store    *session.Store
	registry *prometheus.Registry
	events   *eventRecorder
	logs     *bytes.Buffer // what the Logger wrote; read it only after the server stopped
}

type harnessOptions struct {
	signer           *jwt.Signer
	apiKeys          bool
	apiKeyResolver   apikey.Resolver
	jwtHeader        string
	identityEndpoint bool
	sampleRate       int
	routes           []auth.Route
	readinessCheck   func(ctx context.Context) error
	emitter          wideevent.Emitter // replaces the event recorder
}

func newHarness(t *testing.T, options harnessOptions) *harness {
	t.Helper()
	registry := prometheus.NewRegistry()
	counter, err := prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: metricsNamespace})
	require.NoError(t, err)
	observer := NewObserver(counter)
	store := newTestStore(t)
	guard, err := session.NewGuard(&session.GuardOptions{Store: store, LoginURL: testLoginURL, ReturnPathHeader: "X-Forwarded-Uri", Observer: observer})
	require.NoError(t, err)
	events := &eventRecorder{}
	logs := &bytes.Buffer{}
	serverOptions := &ServerOptions{
		Version:          "1.2.3",
		PathPrefix:       "/auth",
		Routes:           options.routes,
		Guard:            guard,
		Signer:           options.signer,
		JWTHeader:        options.jwtHeader,
		IdentityEndpoint: options.identityEndpoint,
		Emitter:          wideevent.EmitterFunc(events.emit),
		Logger:           slog.New(slog.NewJSONHandler(logs, nil)),
		SampleRate:       1,
		MetricsRegistry:  registry,
		ReadinessCheck:   options.readinessCheck,
	}
	if options.emitter != nil {
		serverOptions.Emitter = options.emitter
	}
	if options.sampleRate != 0 {
		serverOptions.SampleRate = options.sampleRate
	}
	if options.apiKeys {
		serverOptions.APIKeys = newTestAPIKeys(t, observer, options.apiKeyResolver)
	}
	server, err := NewServer(serverOptions)
	require.NoError(t, err)
	return &harness{server: server, store: store, registry: registry, events: events, logs: logs}
}

func newTestStore(t *testing.T) *session.Store {
	t.Helper()
	backend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	return store
}

func newTestAPIKeys(t *testing.T, observer auth.Observer, resolver apikey.Resolver) *apikey.Authenticator {
	t.Helper()
	authenticator, err := apikey.New(&apikey.Options{
		Keys:     []apikey.Key{{Name: testKeyName, Secret: testAPIKey, Permissions: []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}}}},
		Resolver: resolver,
		Observer: observer,
	})
	require.NoError(t, err)
	return authenticator
}

func newTestSigner(t *testing.T) *jwt.Signer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	signer, err := jwt.NewSigner(&jwt.SignerOptions{PrivateKey: pemBytes, Issuer: testIssuer})
	require.NoError(t, err)
	return signer
}

// signIn stores identity in a new session and returns its cookie.
func (h *harness) signIn(t *testing.T, identity *auth.Identity) *http.Cookie {
	t.Helper()
	recorder := httptest.NewRecorder()
	current, err := h.store.Start(t.Context(), recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	require.NoError(t, err)
	require.NoError(t, current.SaveIdentity(t.Context(), identity))
	cookies := recorder.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

// serve runs one request through the real engine.
func (h *harness) serve(t *testing.T, method, target string, header http.Header, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for name, values := range header {
		request.Header[name] = values
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	h.server.engine.ServeHTTP(recorder, request)
	return recorder
}

func testIdentity() *auth.Identity {
	return &auth.Identity{Provider: "oidc", Subject: "user-1", Username: "alice", Active: true, Roles: []string{"admin"}}
}
