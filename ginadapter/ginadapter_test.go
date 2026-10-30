package ginadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	wideevent "github.com/govengers/wide-event-logger"
	wideeventgin "github.com/govengers/wide-event-logger/ginadapter"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/ginadapter"
	"github.com/govengers/auth/session"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

var userID = uuid.MustParse("0b6f2c1e-7a3d-4c55-9f0e-2d8b1a6c4e71")

// newEngine returns an engine with the wide-event middleware in front and a pointer to the event it emits.
func newEngine(t *testing.T) (*gin.Engine, *map[string]any) {
	t.Helper()
	emitted := map[string]any(nil)
	wideEvents, err := wideeventgin.NewMiddleware(&wideeventgin.Options{Emitter: wideevent.EmitterFunc(func(we *wideevent.Event) {
		emitted = we.FieldsMap()
	})})
	require.NoError(t, err)
	engine := gin.New()
	engine.Use(wideEvents)
	return engine, &emitted
}

func serve(t *testing.T, engine *gin.Engine, method string, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), method, path, nil))
	return recorder
}

// authenticateAs is net/http middleware that stands in for a session.Guard or an apikey.Authenticator:
// it passes the request on with identity, or refuses it with 401 when identity is nil.
func authenticateAs(identity *auth.Identity) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if identity == nil {
				auth.WriteError(writer, auth.ErrUnauthenticated)
				return
			}
			next.ServeHTTP(writer, request.WithContext(auth.WithIdentity(request.Context(), identity)))
		})
	}
}

func writeSubject(ginContext *gin.Context) {
	ginContext.String(http.StatusOK, auth.IdentityFrom(ginContext.Request.Context()).Subject)
}

func TestMiddlewarePassesTheEnrichedRequest(t *testing.T) {
	engine, emitted := newEngine(t)
	identity := &auth.Identity{Provider: "password", Subject: "ada", Active: true}
	engine.GET("/me", ginadapter.Middleware(authenticateAs(identity)), func(ginContext *gin.Context) {
		wideevent.FromContext(ginContext.Request.Context()).String("handler.reached", "yes")
		writeSubject(ginContext)
	})

	recorder := serve(t, engine, http.MethodGet, "/me")

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "ada", recorder.Body.String())
	require.Equal(t, map[string]any{"reached": "yes"}, (*emitted)["handler"], "the enriched request keeps the wide event")
}

func TestMiddlewareAbortsWhenItRefuses(t *testing.T) {
	engine, _ := newEngine(t)
	reached := false
	engine.GET("/me", ginadapter.Middleware(authenticateAs(nil)), func(*gin.Context) { reached = true })

	recorder := serve(t, engine, http.MethodGet, "/me")

	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	require.JSONEq(t, `{"code":"unauthenticated","message":"authentication required"}`, recorder.Body.String())
	require.False(t, reached)
}

// firstRequestOnly is net/http middleware with state across requests: it passes the first request and
// refuses every later one with 403. wraps counts how often it wrapped a next handler.
func firstRequestOnly(wraps *atomic.Int32) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		wraps.Add(1)
		var used atomic.Bool
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if used.Swap(true) {
				auth.WriteError(writer, auth.ErrForbidden)
				return
			}
			next.ServeHTTP(writer, request)
		})
	}
}

func TestMiddlewareWrapsOnce(t *testing.T) {
	engine, _ := newEngine(t)
	var wraps atomic.Int32
	engine.GET("/once", ginadapter.Middleware(firstRequestOnly(&wraps)), func(ginContext *gin.Context) { ginContext.Status(http.StatusNoContent) })

	first := serve(t, engine, http.MethodGet, "/once")
	second := serve(t, engine, http.MethodGet, "/once")

	require.Equal(t, http.StatusNoContent, first.Code)
	require.Equal(t, http.StatusForbidden, second.Code, "the middleware's state survives the first request")
	require.Equal(t, int32(1), wraps.Load())
}

func TestMiddlewareKeepsConcurrentRequestsApart(t *testing.T) {
	engine := gin.New()
	subjectFromHeader := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			identity := &auth.Identity{Provider: "password", Subject: request.Header.Get("X-Subject"), Active: true}
			next.ServeHTTP(writer, request.WithContext(auth.WithIdentity(request.Context(), identity)))
		})
	}
	engine.GET("/me", ginadapter.Middleware(subjectFromHeader), writeSubject)

	var waitGroup sync.WaitGroup
	bodies := make([]string, 16)
	for index := range bodies {
		waitGroup.Go(func() {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/me", nil)
			request.Header.Set("X-Subject", fmt.Sprintf("user-%d", index))
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, request)
			bodies[index] = recorder.Body.String()
		})
	}
	waitGroup.Wait()

	for index, body := range bodies {
		require.Equal(t, fmt.Sprintf("user-%d", index), body)
	}
}

func TestMiddlewareFailsWhenTheRequestLosesItsChain(t *testing.T) {
	engine, _ := newEngine(t)
	reached := false
	detached := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			next.ServeHTTP(writer, request.WithContext(context.Background()))
		})
	}
	engine.GET("/me", ginadapter.Middleware(detached), func(*gin.Context) { reached = true })

	recorder := serve(t, engine, http.MethodGet, "/me")

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.JSONEq(t, `{"code":"internal","message":"internal error"}`, recorder.Body.String())
	require.False(t, reached)
}

func TestRegisterRoutes(t *testing.T) {
	engine, _ := newEngine(t)
	fullPath := ""
	engine.Use(func(ginContext *gin.Context) {
		ginContext.Next()
		fullPath = ginContext.FullPath()
	})
	noContent := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	ginadapter.RegisterRoutes(engine, []auth.Route{
		{Method: http.MethodGet, Path: "/auth/github/login", Handler: noContent},
		{Method: http.MethodPost, Path: "/auth/password/logout", Handler: noContent},
	})

	testCases := []struct {
		name         string
		method       string
		path         string
		wantStatus   int
		wantFullPath string
	}{
		{name: "GET route", method: http.MethodGet, path: "/auth/github/login", wantStatus: http.StatusNoContent, wantFullPath: "/auth/github/login"},
		{name: "POST route", method: http.MethodPost, path: "/auth/password/logout", wantStatus: http.StatusNoContent, wantFullPath: "/auth/password/logout"},
		{name: "wrong method", method: http.MethodGet, path: "/auth/password/logout", wantStatus: http.StatusNotFound},
		{name: "unknown path", method: http.MethodGet, path: "/auth/other", wantStatus: http.StatusNotFound},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := serve(t, engine, testCase.method, testCase.path)

			require.Equal(t, testCase.wantStatus, recorder.Code)
			require.Equal(t, testCase.wantFullPath, fullPath)
		})
	}
}

func TestObserve(t *testing.T) {
	cause := errors.New("token revocation failed")
	invalidKey := &auth.Error{Kind: auth.ErrUnauthenticated, Code: "invalid_api_key", Reason: "unknown key"}
	identity := &auth.Identity{
		Provider: "github", Subject: "42", UserID: userID, Username: "ada", Name: "Ada Lovelace", Email: "ada@example.com", Active: true,
	}
	impersonated := &auth.Identity{Provider: "password", Subject: "user-7", Active: true, Impersonator: &auth.Identity{Provider: "password", Subject: "admin-1"}}

	testCases := []struct {
		name    string
		outcome auth.Outcome
		want    map[string]any
	}{
		{
			name:    "login success answers the request",
			outcome: auth.Outcome{Provider: "github", Action: auth.ActionCallback, Result: auth.ResultSuccess, Identity: identity},
			want: map[string]any{
				"auth":    map[string]any{"provider": "github", "action": "callback", "result": "success", "subject": "42"},
				"user":    map[string]any{"id": userID.String()},
				"outcome": "success",
			},
		},
		{
			name:    "challenge answers the request",
			outcome: auth.Outcome{Provider: "password", Action: auth.ActionLogin, Result: auth.ResultChallenge},
			want: map[string]any{
				"auth":    map[string]any{"provider": "password", "action": "login", "result": "challenge"},
				"outcome": "success",
			},
		},
		{
			name:    "authentication success leaves the outcome to the handler",
			outcome: auth.Outcome{Provider: "github", Action: auth.ActionAuthenticate, Result: auth.ResultSuccess, Identity: identity},
			want: map[string]any{
				"auth": map[string]any{"provider": "github", "action": "authenticate", "result": "success", "subject": "42"},
				"user": map[string]any{"id": userID.String()},
			},
		},
		{
			name:    "refresh success leaves the outcome to the handler",
			outcome: auth.Outcome{Provider: "password", Action: auth.ActionRefresh, Result: auth.ResultSuccess},
			want:    map[string]any{"auth": map[string]any{"refresh": map[string]any{"provider": "password", "action": "refresh", "result": "success"}}},
		},
		{
			name:    "refresh denial records under auth.refresh without the user ID",
			outcome: auth.Outcome{Provider: "github", Action: auth.ActionRefresh, Result: auth.ResultDenied, Err: auth.ErrForbidden, Identity: identity},
			want: map[string]any{
				"auth":    map[string]any{"refresh": map[string]any{"provider": "github", "action": "refresh", "result": "denied", "code": "forbidden", "subject": "42"}},
				"outcome": "failure",
				"error":   "forbidden",
			},
		},
		{
			name:    "impersonation start records under auth.impersonation and answers the request",
			outcome: auth.Outcome{Provider: "password", Action: auth.ActionImpersonationStart, Result: auth.ResultSuccess, Identity: impersonated},
			want: map[string]any{
				"auth": map[string]any{"impersonation": map[string]any{
					"provider": "password", "action": "impersonation_start", "result": "success", "subject": "admin-1", "impersonating": true, "impersonated_subject": "user-7",
				}},
				"outcome": "success",
			},
		},
		{
			name:    "impersonation stop denial records under auth.impersonation",
			outcome: auth.Outcome{Provider: "password", Action: auth.ActionImpersonationStop, Result: auth.ResultDenied, Err: &auth.Error{Kind: auth.ErrConflict, Code: "not_impersonating"}, Identity: identity},
			want: map[string]any{
				"auth":    map[string]any{"impersonation": map[string]any{"provider": "password", "action": "impersonation_stop", "result": "denied", "code": "not_impersonating", "subject": "42"}},
				"outcome": "failure",
				"error":   "conflict: not_impersonating",
			},
		},
		{
			name:    "impersonation records the real subject and the acting user ID",
			outcome: auth.Outcome{Provider: "session", Action: auth.ActionAuthenticate, Result: auth.ResultSuccess, Identity: impersonated},
			want: map[string]any{
				"auth": map[string]any{"provider": "session", "action": "authenticate", "result": "success", "subject": "admin-1", "impersonating": true, "impersonated_subject": "user-7"},
			},
		},
		{
			name:    "denial records code, reason and failure",
			outcome: auth.Outcome{Provider: "apikey", Action: auth.ActionAuthenticate, Result: auth.ResultDenied, Err: invalidKey},
			want: map[string]any{
				"auth":    map[string]any{"provider": "apikey", "action": "authenticate", "result": "denied", "code": "invalid_api_key", "reason": "unknown key"},
				"outcome": "failure",
				"error":   "unauthenticated: invalid_api_key: unknown key",
			},
		},
		{
			name:    "denial by a bare sentinel has no reason",
			outcome: auth.Outcome{Provider: "session", Action: auth.ActionAuthenticate, Result: auth.ResultDenied, Err: auth.ErrUnauthenticated},
			want: map[string]any{
				"auth":    map[string]any{"provider": "session", "action": "authenticate", "result": "denied", "code": "unauthenticated"},
				"outcome": "failure",
				"error":   "unauthenticated",
			},
		},
		{
			name:    "internal failure records the error",
			outcome: auth.Outcome{Provider: "apikey", Action: auth.ActionAuthenticate, Result: auth.ResultError, Err: cause},
			want: map[string]any{
				"auth":    map[string]any{"provider": "apikey", "action": "authenticate", "result": "error", "code": "internal", "error": "token revocation failed"},
				"outcome": "failure",
				"error":   "token revocation failed",
			},
		},
		{
			name:    "success with an error is degraded",
			outcome: auth.Outcome{Provider: "github", Action: auth.ActionLogout, Result: auth.ResultSuccess, Err: cause, Identity: identity},
			want: map[string]any{
				"auth":     map[string]any{"provider": "github", "action": "logout", "result": "success", "code": "internal", "error": "token revocation failed", "subject": "42"},
				"user":     map[string]any{"id": userID.String()},
				"degraded": true,
				"outcome":  "success",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fields := emittedFields(t, func(ctx context.Context) { ginadapter.Observe(ctx, testCase.outcome) })

			require.Equal(t, testCase.want, fields)
		})
	}
}

// emittedFields runs record inside a unit of work and returns what the emitted event carries besides its
// name and duration.
func emittedFields(t *testing.T, record func(ctx context.Context)) map[string]any {
	t.Helper()
	emitted := false
	we := wideevent.Begin(wideevent.EmitterFunc(func(*wideevent.Event) { emitted = true }), "test")

	record(wideevent.NewContext(t.Context(), we))
	we.Emit()

	require.True(t, emitted)
	fields := we.FieldsMap()
	delete(fields, "name")
	delete(fields, "duration")
	return fields
}

func TestObserveKeepsARefreshApartFromTheAuthentication(t *testing.T) {
	identity := &auth.Identity{Provider: "github", Subject: "42", UserID: userID, Active: true}

	fields := emittedFields(t, func(ctx context.Context) {
		ginadapter.Observe(ctx, auth.Outcome{Provider: "github", Action: auth.ActionRefresh, Result: auth.ResultSuccess, Err: errors.New("github api: 503"), Identity: identity})
		ginadapter.Observe(ctx, auth.Outcome{Provider: "github", Action: auth.ActionAuthenticate, Result: auth.ResultSuccess, Identity: identity})
	})

	require.Equal(t, map[string]any{
		"auth": map[string]any{
			"provider": "github", "action": "authenticate", "result": "success", "subject": "42",
			"refresh": map[string]any{"provider": "github", "action": "refresh", "result": "success", "code": "internal", "error": "github api: 503", "subject": "42"},
		},
		"user":     map[string]any{"id": userID.String()},
		"degraded": true,
	}, fields)
}

// failingRefresher is a session.Refresher for "github" whose identity provider is down.
type failingRefresher struct{}

func (failingRefresher) Name() string { return "github" }

func (failingRefresher) Refresh(context.Context, session.Session, *auth.Identity) (*auth.Identity, error) {
	return nil, errors.New("github api: 503")
}

func TestObserveRecordsAGuardRefreshOnce(t *testing.T) {
	backend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	login := httptest.NewRecorder()
	started, err := store.Start(t.Context(), login, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	require.NoError(t, err)
	require.NoError(t, started.SaveIdentity(t.Context(), &auth.Identity{Provider: "github", Subject: "42", UserID: userID, Active: true}))
	// Every request is due for a refresh: the stored identity was refreshed more than a nanosecond ago.
	// The Guard's clock cannot be set from this package, so a short interval through the options stands in
	// for it (TST-005); sealing the session and the request in between take far longer than a nanosecond.
	guard, err := session.NewGuard(&session.GuardOptions{Store: store, Refreshers: []session.Refresher{failingRefresher{}}, RefreshInterval: time.Nanosecond, Observer: ginadapter.Observe})
	require.NoError(t, err)
	engine, emitted := newEngine(t)
	engine.GET("/me", ginadapter.Middleware(guard.RequireAPI()), writeSubject)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/me", nil)
	for _, cookie := range login.Result().Cookies() {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()

	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	authFields, _ := (*emitted)["auth"].(map[string]any)
	require.Equal(t, "authenticate", authFields["action"])
	require.NotContains(t, authFields, "error", "the refresh's failure is not the authentication's")
	require.Equal(t, map[string]any{"provider": "github", "action": "refresh", "result": "success", "code": "internal", "error": "github api: 503", "subject": "42"}, authFields["refresh"])
	require.Equal(t, true, (*emitted)["degraded"])
}

func TestTheDeprecatedRedactQueryLeavesTheRedactedQuery(t *testing.T) {
	output := &bytes.Buffer{}
	wideEvents, err := wideeventgin.NewMiddleware(&wideeventgin.Options{
		Emitter:     wideevent.NewJSONEmitter(&wideevent.JSONEmitterOptions{Writer: output}),
		PreEnricher: ginadapter.RedactQuery,
	})
	require.NoError(t, err)
	engine := gin.New()
	engine.Use(wideEvents)
	engine.GET("/callback", func(ginContext *gin.Context) { ginContext.Status(http.StatusFound) })

	serve(t, engine, http.MethodGet, "/callback?code=secret-code&state=secret-state")

	event := map[string]any{}
	require.NoError(t, json.Unmarshal(output.Bytes(), &event))
	require.Equal(t, "code=redacted&state=redacted", event["request"].(map[string]any)["query"])
	require.NotContains(t, output.String(), "secret-")
}

func TestObserveWithoutWideEvent(t *testing.T) {
	require.NotPanics(t, func() {
		ginadapter.Observe(t.Context(), auth.Outcome{Provider: "github", Action: auth.ActionLogin, Result: auth.ResultDenied, Err: auth.ErrForbidden})
	})
}

func TestRequire(t *testing.T) {
	admin := &auth.Identity{Provider: "password", Subject: "admin-1", Active: true, Roles: []string{auth.RoleAdmin}}
	user := &auth.Identity{Provider: "password", Subject: "user-7", Active: true}
	lookupFailed := func(context.Context) error { return errors.New("membership lookup failed") }

	testCases := []struct {
		name              string
		identity          *auth.Identity
		check             authorization.Check
		wantStatus        int
		wantBody          string
		wantAuthorization map[string]any
		wantOutcome       string
		wantError         string
	}{
		{
			name: "allowed continues", identity: admin, check: authorization.IsAdmin(),
			wantStatus: http.StatusOK, wantBody: "admin-1", wantOutcome: "success",
		},
		{
			name: "no identity is 401", check: authorization.IsAdmin(),
			wantStatus: http.StatusUnauthorized, wantBody: `{"code":"unauthenticated","message":"authentication required"}`,
			wantAuthorization: map[string]any{"denied": true, "reason": "no identity"},
			wantOutcome:       "failure", wantError: "unauthenticated: no identity",
		},
		{
			name: "forbidden is 403 without the reason", identity: user, check: authorization.IsAdmin(),
			wantStatus: http.StatusForbidden, wantBody: `{"code":"forbidden","message":"access denied"}`,
			wantAuthorization: map[string]any{"denied": true, "reason": "missing role admin"},
			wantOutcome:       "failure", wantError: "forbidden: missing role admin",
		},
		{
			name: "refusal without a reason", identity: user, check: func(context.Context) error { return &auth.Error{Kind: auth.ErrForbidden} },
			wantStatus: http.StatusForbidden, wantBody: `{"code":"forbidden","message":"access denied"}`,
			wantAuthorization: map[string]any{"denied": true},
			wantOutcome:       "failure", wantError: "forbidden",
		},
		{
			name: "internal error is 500", identity: user, check: lookupFailed,
			wantStatus: http.StatusInternalServerError, wantBody: `{"code":"internal","message":"internal error"}`,
			wantAuthorization: map[string]any{"denied": true, "reason": "membership lookup failed", "error": "membership lookup failed"},
			wantOutcome:       "failure", wantError: "membership lookup failed",
		},
		{
			name: "nil check is 500", identity: admin,
			wantStatus: http.StatusInternalServerError, wantBody: `{"code":"internal","message":"internal error"}`,
			wantAuthorization: map[string]any{"denied": true, "reason": "authorization check is nil", "error": "authorization check is nil"},
			wantOutcome:       "failure", wantError: "authorization check is nil",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			engine, emitted := newEngine(t)
			engine.GET("/admin", ginadapter.Middleware(authenticateOptionally(testCase.identity)), ginadapter.Require(testCase.check), func(ginContext *gin.Context) {
				wideevent.FromContext(ginContext.Request.Context()).Success()
				writeSubject(ginContext)
			})

			recorder := serve(t, engine, http.MethodGet, "/admin")

			require.Equal(t, testCase.wantStatus, recorder.Code)
			require.Equal(t, testCase.wantBody, strings.TrimSuffix(recorder.Body.String(), "\n"))
			if testCase.wantStatus != http.StatusOK {
				require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			}
			fields := *emitted
			if testCase.wantAuthorization == nil {
				require.NotContains(t, fields, "authorization")
			} else {
				require.Equal(t, testCase.wantAuthorization, fields["authorization"])
			}
			require.Equal(t, testCase.wantOutcome, fields["outcome"])
			if testCase.wantError == "" {
				require.NotContains(t, fields, "error")
			} else {
				require.Equal(t, testCase.wantError, fields["error"])
			}
		})
	}
}

// authenticateOptionally passes every request on, with identity when there is one.
func authenticateOptionally(identity *auth.Identity) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			next.ServeHTTP(writer, request.WithContext(auth.WithIdentity(request.Context(), identity)))
		})
	}
}

func TestRequireMethodPermission(t *testing.T) {
	withPermission := func(permission auth.Permission) *auth.Identity {
		return &auth.Identity{Provider: "apikey", Subject: "ci", Active: true, Permissions: []auth.Permission{permission}}
	}
	reader := withPermission(auth.Permission{Resource: "builds", Access: auth.AccessRead})
	writer := withPermission(auth.Permission{Resource: "*", Access: auth.AccessWrite})

	testCases := []struct {
		name       string
		method     string
		identity   *auth.Identity
		wantStatus int
		wantReason any
	}{
		{name: "GET with read passes", method: http.MethodGet, identity: reader, wantStatus: http.StatusOK},
		{name: "HEAD with read passes", method: http.MethodHead, identity: reader, wantStatus: http.StatusOK},
		{name: "OPTIONS with read passes", method: http.MethodOptions, identity: reader, wantStatus: http.StatusOK},
		{name: "POST with read is 403", method: http.MethodPost, identity: reader, wantStatus: http.StatusForbidden, wantReason: "missing permission builds:write"},
		{name: "DELETE with read is 403", method: http.MethodDelete, identity: reader, wantStatus: http.StatusForbidden, wantReason: "missing permission builds:write"},
		{name: "POST with wildcard write passes", method: http.MethodPost, identity: writer, wantStatus: http.StatusOK},
		{name: "GET with wildcard write passes", method: http.MethodGet, identity: writer, wantStatus: http.StatusOK},
		{name: "no identity is 401", method: http.MethodGet, wantStatus: http.StatusUnauthorized, wantReason: "no identity"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			engine, emitted := newEngine(t)
			engine.Any("/builds", ginadapter.Middleware(authenticateOptionally(testCase.identity)), ginadapter.RequireMethodPermission("builds"), func(ginContext *gin.Context) {
				ginContext.Status(http.StatusOK)
			})

			recorder := serve(t, engine, testCase.method, "/builds")

			require.Equal(t, testCase.wantStatus, recorder.Code)
			if testCase.wantReason == nil {
				require.NotContains(t, *emitted, "authorization")
				return
			}
			require.Equal(t, map[string]any{"denied": true, "reason": testCase.wantReason}, (*emitted)["authorization"])
			require.Equal(t, "failure", (*emitted)["outcome"])
		})
	}
}

func TestRequireWithoutWideEvent(t *testing.T) {
	engine := gin.New()
	engine.GET("/admin", ginadapter.Require(authorization.IsAdmin()))

	recorder := serve(t, engine, http.MethodGet, "/admin")

	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}
