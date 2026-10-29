package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/govengers/auth"
)

func ExampleResponseFor() {
	refusal := &auth.Error{Kind: auth.ErrForbidden, Reason: "missing role admin"}

	status, response := auth.ResponseFor(fmt.Errorf("open report: %w", refusal))

	fmt.Println(status, response.Code, response.Message)
	// Output: 403 forbidden access denied
}

func ExampleIdentityFrom() {
	identity := &auth.Identity{Provider: "password", Subject: "ada", Active: true}

	ctx := auth.WithIdentity(context.Background(), identity)

	fmt.Println(auth.IdentityFrom(ctx).Subject)
	// Output: ada
}

func ExampleIdentityHandler() {
	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, []auth.Route{
		{Method: http.MethodGet, Path: "/auth/me", Handler: auth.IdentityHandler()},
	})
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Provider: "github", Subject: "42", Active: true})
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/me", nil)
	recorder := httptest.NewRecorder()

	serveMux.ServeHTTP(recorder, request)

	fmt.Print(recorder.Code, " ", recorder.Body.String())
	// Output: 200 {"provider":"github","subject":"42","active":true,"roles":[]}
}

func ExampleIdentity_Clone() {
	identity := &auth.Identity{Provider: "github", Subject: "42", Roles: []string{"reader"}}

	promoted := identity.Clone()
	promoted.Roles = append(promoted.Roles, auth.RoleAdmin)

	fmt.Println(identity.Roles, promoted.Roles)
	// Output: [reader] [reader admin]
}

func ExampleParsePermission() {
	permission, err := auth.ParsePermission("builds:write")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(permission.Allows("builds", auth.AccessRead), permission.Allows("deployments", auth.AccessRead))
	fmt.Println(auth.AccessForMethod(http.MethodDelete))
	// Output:
	// true false
	// write
}
