package password_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/google/uuid"

	"github.com/govengers/auth"
	"github.com/govengers/auth/password"
	"github.com/govengers/auth/session"
)

// newExampleSessions builds a session store on the in-process backend; production code shares a Redis
// backend between replicas and reads the key from its configuration.
func newExampleSessions() (*session.Store, error) {
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

// newExampleStorage stands in for the application's user table with one user, ada.
func newExampleStorage() (*password.MemoryStorage, error) {
	storage := password.NewMemoryStorage()
	hash, err := password.Hash("correct horse battery staple", password.DefaultParameters())
	if err != nil {
		return nil, err
	}
	ada := &password.User{ID: uuid.MustParse("6f1c2a4e-8d3b-4f5a-9c7e-1b2d3e4f5a6b"), Username: new("ada"), PasswordHash: hash}
	return storage, storage.CreateUser(context.Background(), ada)
}

// send serves request on handler with the cookies an earlier response set, as a browser would.
func send(handler http.Handler, request *http.Request, earlier *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	if earlier != nil {
		for _, line := range earlier.Header().Values("Set-Cookie") {
			if cookie, err := http.ParseSetCookie(line); err == nil {
				request.AddCookie(cookie)
			}
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func ExampleNew() {
	sessions, err := newExampleSessions()
	if err != nil {
		fmt.Println(err)
		return
	}
	storage, err := newExampleStorage()
	if err != nil {
		fmt.Println(err)
		return
	}
	provider, err := password.New(&password.Options{Sessions: sessions, Storage: storage})
	if err != nil {
		fmt.Println(err)
		return
	}
	// The provider is the Guard's Refresher, so deleting a user ends their sessions within a minute.
	guard, err := session.NewGuard(&session.GuardOptions{Store: sessions, Refreshers: []session.Refresher{provider}})
	if err != nil {
		fmt.Println(err)
		return
	}
	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes())
	serveMux.Handle("GET /auth/me", guard.RequireAPI()(auth.IdentityHandler()))

	loginRequest := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/password/login",
		strings.NewReader(`{"identifier":"ada","password":"correct horse battery staple"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	login := send(serveMux, loginRequest, nil)
	currentUser := send(serveMux, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/me", nil), login)

	fmt.Print(login.Code, " ", login.Body.String())
	fmt.Print(currentUser.Code, " ", currentUser.Body.String())
	// Output:
	// 200 {"provider":"password","subject":"6f1c2a4e-8d3b-4f5a-9c7e-1b2d3e4f5a6b","userId":"6f1c2a4e-8d3b-4f5a-9c7e-1b2d3e4f5a6b","username":"ada","active":true,"roles":[]}
	// 200 {"provider":"password","subject":"6f1c2a4e-8d3b-4f5a-9c7e-1b2d3e4f5a6b","userId":"6f1c2a4e-8d3b-4f5a-9c7e-1b2d3e4f5a6b","username":"ada","active":true,"roles":[]}
}

func ExampleProvider_Routes() {
	sessions, err := newExampleSessions()
	if err != nil {
		fmt.Println(err)
		return
	}
	provider, err := password.New(&password.Options{
		Sessions:           sessions,
		Storage:            password.NewMemoryStorage(),
		EnableRegistration: true,
		TOTP:               password.TOTPOptions{Enabled: true, Issuer: "Example"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, route := range provider.Routes() {
		fmt.Println(route.Method, route.Path)
	}
	// Output:
	// POST /auth/password/login
	// POST /auth/password/logout
	// POST /auth/password/register
	// POST /auth/password/totp/verify
	// GET /auth/password/totp
	// POST /auth/password/totp/setup
	// POST /auth/password/totp/enable
	// POST /auth/password/totp/disable
}
