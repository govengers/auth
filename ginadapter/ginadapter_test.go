package ginadapter_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	wideevent "github.com/mxcd/go-wide-event-logger"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/ginadapter"
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
	engine := gin.New()
	engine.Use(wideevent.Middleware(wideevent.WithEmitter(wideevent.EmitterFunc(func(we *wideevent.Event) {
		emitted = we.FieldsMap()
	}))))
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
		wideevent.FromContext(ginContext.Request.Context()).Str("handler.reached", "yes")
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
			want:    map[string]any{"auth": map[string]any{"provider": "password", "action": "refresh", "result": "success"}},
		},
		{
			name:    "impersonation records the real subject and the acting user ID",
			outcome: auth.Outcome{Provider: "session", Action: auth.ActionAuthenticate, Result: auth.ResultSuccess, Identity: impersonated},
			want: map[string]any{
				"auth": map[string]any{"provider": "session", "action": "authenticate", "result": "success", "subject": "admin-1", "impersonating": true},
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
// name and duration. It fails the test when a key was set twice.
func emittedFields(t *testing.T, record func(ctx context.Context)) map[string]any {
	t.Helper()
	emitted := false
	we := wideevent.Begin(wideevent.EmitterFunc(func(*wideevent.Event) { emitted = true }), "test")

	record(wideevent.NewContext(t.Context(), we))
	we.Emit()

	require.True(t, emitted)
	keys := map[string]bool{}
	for _, field := range we.Fields() {
		require.False(t, keys[field.Key], "key %s set twice", field.Key)
		keys[field.Key] = true
	}
	fields := we.FieldsMap()
	delete(fields, "name")
	delete(fields, "duration")
	return fields
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

func TestRequireWithoutWideEvent(t *testing.T) {
	engine := gin.New()
	engine.GET("/admin", ginadapter.Require(authorization.IsAdmin()))

	recorder := serve(t, engine, http.MethodGet, "/admin")

	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}
