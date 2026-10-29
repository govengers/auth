package apikey_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
)

func ExampleNew() {
	authenticator, err := apikey.New(&apikey.Options{
		Keys: []apikey.Key{{
			Name:        "ci",
			Secret:      "ci-secret-0123456789",
			Roles:       []string{auth.RoleAdmin},
			Permissions: []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}},
		}},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	protected := authenticator.Middleware()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := auth.IdentityFrom(request.Context())
		fmt.Fprintln(writer, identity.Subject, identity.Roles, identity.Permissions)
	}))

	for _, key := range []string{"ci-secret-0123456789", "guess"} {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/builds", nil)
		request.Header.Set("X-API-Key", key)
		recorder := httptest.NewRecorder()
		protected.ServeHTTP(recorder, request)
		fmt.Print(recorder.Code, " ", recorder.Body.String())
	}
	// Output:
	// 200 ci [admin] [builds:write]
	// 401 {"code":"invalid_api_key","message":"authentication required"}
}
