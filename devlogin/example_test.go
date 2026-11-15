package devlogin_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/google/uuid"

	"github.com/govengers/auth"
	"github.com/govengers/auth/devlogin"
	"github.com/govengers/auth/session"
)

// developmentConfiguration stands in for the application's configuration: DEV_LOGIN switches the provider on
// and must come with an insecure (plain HTTP) session cookie, so it cannot be left on behind TLS in production.
type developmentConfiguration struct {
	DevLogin       bool
	InsecureCookie bool
}

func Example() {
	configuration := developmentConfiguration{DevLogin: true, InsecureCookie: true}
	backend, err := session.NewMemoryBackend(nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	key, err := session.ParseKey("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		fmt.Println(err)
		return
	}
	sessions, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key, InsecureCookie: configuration.InsecureCookie})
	if err != nil {
		fmt.Println(err)
		return
	}
	serveMux := http.NewServeMux()
	if configuration.DevLogin {
		if !configuration.InsecureCookie {
			fmt.Println("DEV_LOGIN needs SESSION_INSECURE_COOKIE: dev login is for local plain HTTP only")
			return
		}
		ada := &auth.Identity{UserID: uuid.MustParse("6f1c2a4e-8d3b-4f5a-9c7e-1b2d3e4f5a6b"), Username: "ada", Roles: []string{auth.RoleAdmin}, Active: true}
		provider, err := devlogin.New(&devlogin.Options{
			Enabled:  true,
			Sessions: sessions,
			Users: func(context.Context) ([]devlogin.User, error) {
				return []devlogin.User{{ID: "ada", Name: "Ada Lovelace", Description: "admin"}}, nil
			},
			Load: func(_ context.Context, id string) (*auth.Identity, error) {
				if id != "ada" {
					return nil, nil
				}
				return ada, nil
			},
		})
		if err != nil {
			fmt.Println(err)
			return
		}
		auth.RegisterRoutes(serveMux, provider.Routes())
	}

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/dev/login", strings.NewReader(`{"id":"ada"}`))
	request.RemoteAddr, request.Host = "127.0.0.1:52100", "localhost:8080"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	serveMux.ServeHTTP(recorder, request)
	fmt.Println(recorder.Code, strings.TrimSpace(recorder.Body.String()))
	// Output:
	// 200 {"provider":"dev","subject":"ada","userId":"6f1c2a4e-8d3b-4f5a-9c7e-1b2d3e4f5a6b","username":"ada","active":true,"roles":["admin"]}
}
