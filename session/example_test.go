package session_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

// newExampleStore builds a store on the in-process backend; production code shares a Redis backend
// between replicas and reads the key from its configuration.
func newExampleStore() (*session.Store, error) {
	backend, err := session.NewMemoryBackend(nil)
	if err != nil {
		return nil, err
	}
	key, err := session.ParseKey("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		return nil, err
	}
	return session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key})
}

// loginHandler stands in for a provider: it starts a fresh session and saves the identity in it.
func loginHandler(store *session.Store) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current, err := store.Start(request.Context(), writer, request)
		if err != nil {
			auth.WriteError(writer, err)
			return
		}
		identity := &auth.Identity{Provider: "password", Subject: "user-1", Username: "ada", Active: true}
		if err := current.SaveIdentity(request.Context(), identity); err != nil {
			auth.WriteError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

// withCookies returns a GET request to target carrying the cookies response set, as a browser would.
func withCookies(target string, response *httptest.ResponseRecorder) *http.Request {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	for _, line := range response.Header().Values("Set-Cookie") {
		if cookie, err := http.ParseSetCookie(line); err == nil {
			request.AddCookie(cookie)
		}
	}
	return request
}

func ExampleStore() {
	store, err := newExampleStore()
	if err != nil {
		fmt.Println(err)
		return
	}
	login := httptest.NewRecorder()
	loginHandler(store).ServeHTTP(login, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login", nil))

	current, err := store.Open(withCookies("/", login))
	if err != nil {
		fmt.Println(err)
		return
	}
	identity, err := current.Identity(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(identity.Provider, identity.Username)
	// Output: password ada
}

func ExampleGuard() {
	store, err := newExampleStore()
	if err != nil {
		fmt.Println(err)
		return
	}
	guard, err := session.NewGuard(&session.GuardOptions{Store: store, LoginURL: "/login"})
	if err != nil {
		fmt.Println(err)
		return
	}
	serveMux := http.NewServeMux()
	serveMux.Handle("POST /login", loginHandler(store))
	serveMux.Handle("GET /api/me", guard.RequireAPI()(auth.IdentityHandler()))
	serveMux.Handle("GET /reports", guard.RequireUI()(http.NotFoundHandler()))

	anonymousAPI := httptest.NewRecorder()
	serveMux.ServeHTTP(anonymousAPI, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/me", nil))
	anonymousUI := httptest.NewRecorder()
	serveMux.ServeHTTP(anonymousUI, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/reports?year=2026", nil))
	login := httptest.NewRecorder()
	serveMux.ServeHTTP(login, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login", nil))
	authenticated := httptest.NewRecorder()
	serveMux.ServeHTTP(authenticated, withCookies("/api/me", login))

	fmt.Print(anonymousAPI.Code, " ", anonymousAPI.Body.String())
	fmt.Println(anonymousUI.Code, anonymousUI.Header().Get("Location"))
	fmt.Print(authenticated.Code, " ", authenticated.Body.String())
	// Output:
	// 401 {"code":"unauthenticated","message":"authentication required"}
	// 302 /login?return_to=%2Freports%3Fyear%3D2026
	// 200 {"provider":"password","subject":"user-1","username":"ada","active":true,"roles":[]}
}

// adminLoginHandler stands in for a provider whose OnLogin grants the admin role.
func adminLoginHandler(store *session.Store) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current, err := store.Start(request.Context(), writer, request)
		if err != nil {
			auth.WriteError(writer, err)
			return
		}
		admin := &auth.Identity{Provider: "password", Subject: "admin-1", Username: "grace", Active: true, Roles: []string{auth.RoleAdmin}}
		if err := current.SaveIdentity(request.Context(), admin); err != nil {
			auth.WriteError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func ExampleImpersonator() {
	store, err := newExampleStore()
	if err != nil {
		fmt.Println(err)
		return
	}
	guard, err := session.NewGuard(&session.GuardOptions{Store: store})
	if err != nil {
		fmt.Println(err)
		return
	}
	users := map[string]*auth.Identity{"user-2": {Provider: "password", Subject: "user-2", Username: "ada", Active: true}}
	impersonator, err := session.NewImpersonator(&session.ImpersonatorOptions{
		Guard: guard,
		// Actor defaults to authorization.IsAdmin(), Target to authorization.Not(authorization.IsAdmin()).
		Load: func(_ context.Context, subject string) (*auth.Identity, error) {
			return users[subject].Clone(), nil // your user table and OnLogin; nil: no such user
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	serveMux := http.NewServeMux()
	serveMux.Handle("POST /login", adminLoginHandler(store))
	serveMux.Handle("GET /api/me", guard.RequireAPI()(auth.IdentityHandler()))
	auth.RegisterRoutes(serveMux, impersonator.Routes()) // POST and DELETE /auth/impersonation

	login := httptest.NewRecorder()
	serveMux.ServeHTTP(login, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login", nil))
	start := withCookies("/auth/impersonation", login)
	start.Method, start.Body = http.MethodPost, io.NopCloser(strings.NewReader(`{"subject":"user-2"}`))
	start.Header.Set("Content-Type", "application/json")
	serveMux.ServeHTTP(httptest.NewRecorder(), start)
	impersonating := httptest.NewRecorder()
	serveMux.ServeHTTP(impersonating, withCookies("/api/me", login))

	fmt.Print(impersonating.Body.String())
	// Output:
	// {"provider":"password","subject":"user-2","username":"ada","active":true,"roles":[],"impersonator":{"provider":"password","subject":"admin-1","username":"grace","active":true,"roles":["admin"]}}
}
