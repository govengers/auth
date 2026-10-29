package authorization_test

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
)

func ExampleAny() {
	ownerID := uuid.MustParse("0b6f2c1e-7a3d-4c55-9f0e-2d8b1a6c4e71")
	ownerOrAdmin := authorization.Any(authorization.IsAdmin(), authorization.HasUserID(ownerID))

	owner := auth.WithIdentity(context.Background(), &auth.Identity{Provider: "password", Subject: "ada", UserID: ownerID, Active: true})
	stranger := auth.WithIdentity(context.Background(), &auth.Identity{Provider: "password", Subject: "eve", UserID: uuid.New(), Active: true})

	fmt.Println(ownerOrAdmin(owner))
	fmt.Println(ownerOrAdmin(stranger))
	fmt.Println(ownerOrAdmin(context.Background()))
	// Output:
	// <nil>
	// forbidden: missing role admin
	// unauthenticated: no identity
}

func ExampleAll() {
	editor := authorization.All(authorization.HasOIDCGroup("/engineering"), authorization.Not(authorization.HasOIDCRole("read-only")))

	engineer := auth.WithIdentity(context.Background(), &auth.Identity{Provider: "keycloak", Subject: "1", Active: true, Groups: []string{"/engineering"}})
	reader := auth.WithIdentity(context.Background(), &auth.Identity{Provider: "keycloak", Subject: "2", Active: true, Groups: []string{"/engineering"}, OIDCRoles: []string{"read-only"}})

	fmt.Println(editor(engineer))
	status, response := auth.ResponseFor(editor(reader))
	fmt.Println(status, response.Code)
	// Output:
	// <nil>
	// 403 forbidden
}

func ExampleHasPermission() {
	continuousIntegration := auth.WithIdentity(context.Background(), &auth.Identity{
		Provider:    "apikey",
		Subject:     "ci",
		Active:      true,
		Permissions: []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}, {Resource: "*", Access: auth.AccessRead}},
	})

	fmt.Println(authorization.HasPermission("builds", auth.AccessWrite)(continuousIntegration))
	fmt.Println(authorization.HasPermission("deployments", auth.AccessRead)(continuousIntegration))
	fmt.Println(authorization.HasPermission("deployments", auth.AccessWrite)(continuousIntegration))
	// Output:
	// <nil>
	// <nil>
	// forbidden: missing permission deployments:write
}
