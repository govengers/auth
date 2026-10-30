package jwt

import (
	"maps"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

func TestIdentityClaimsCopiesOnlyForeignClaims(t *testing.T) {
	foreignClaims := map[string]any{"locale": "de", "realm_access": map[string]any{"roles": []any{"x"}}}
	ownedClaims := map[string]any{
		"iss": "i", "sub": "s", "aud": "a", "exp": 1, "nbf": 1, "iat": 1, "jti": "j", "nonce": "n", "at_hash": "h",
		"c_hash": "h", "auth_time": 1, "sid": "s", "azp": "a", "provider": "p", "user_id": "u", "preferred_username": "u",
		"name": "n", "email": "e", "picture": "p", "roles": []any{auth.RoleAdmin}, "realm_roles": []any{"r"},
		"client_roles": []any{"c"}, "groups": []any{"g"}, "teams": []any{"t"}, "permissions": []any{"*:write"},
		"Roles": []any{auth.RoleAdmin}, "PERMISSIONS": []any{"*:write"}, "Sub": "s", "User_ID": "u",
	}
	allClaims := maps.Clone(ownedClaims)
	maps.Copy(allClaims, foreignClaims)

	claims, err := identityClaims(&auth.Identity{Claims: allClaims})

	require.NoError(t, err)
	require.Equal(t, foreignClaims, claims)
}

func TestIdentityClaimsOmitsEmptyFields(t *testing.T) {
	claims, err := identityClaims(&auth.Identity{Subject: "42", UserID: uuid.Nil, Roles: []string{}, Permissions: []auth.Permission{}})

	require.NoError(t, err)
	require.Equal(t, map[string]any{"sub": "42"}, claims)
}

func TestIdentityClaimsWritesPermissionsAsText(t *testing.T) {
	claims, err := identityClaims(&auth.Identity{Permissions: []auth.Permission{
		{Resource: "builds", Access: auth.AccessWrite},
		{Resource: auth.AllResources, Access: auth.AccessRead},
	}})

	require.NoError(t, err)
	require.Equal(t, map[string]any{"permissions": []string{"builds:write", "*:read"}}, claims)
}

func TestIdentityClaimsRefusesInvalidPermissions(t *testing.T) {
	testCases := []struct {
		name       string
		permission auth.Permission
	}{
		{name: "empty", permission: auth.Permission{}},
		{name: "upper-case resource", permission: auth.Permission{Resource: "Builds", Access: auth.AccessWrite}},
		{name: "unknown access", permission: auth.Permission{Resource: "builds", Access: "admin"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			permissions := []auth.Permission{{Resource: "builds", Access: auth.AccessRead}, testCase.permission}

			claims, err := identityClaims(&auth.Identity{Subject: "42", Permissions: permissions})

			require.ErrorContains(t, err, "permissions claim: permission")
			require.Nil(t, claims)
		})
	}
}

func TestIdentityFromClaimsSkipsWrongTypes(t *testing.T) {
	testCases := []struct {
		name   string
		claims map[string]any
		want   *auth.Identity
	}{
		{name: "string list as string", claims: map[string]any{"roles": auth.RoleAdmin}, want: &auth.Identity{}},
		{name: "string list as object", claims: map[string]any{"groups": map[string]any{"a": "b"}}, want: &auth.Identity{}},
		{name: "string list with other elements", claims: map[string]any{"teams": []any{1.0, "org/team", nil, []any{"x"}}}, want: &auth.Identity{Teams: []string{"org/team"}}},
		{name: "string as number", claims: map[string]any{"sub": 42.0, "name": true}, want: &auth.Identity{}},
		{name: "user ID as number", claims: map[string]any{"user_id": 42.0}, want: &auth.Identity{}},
		{name: "user ID not a UUID", claims: map[string]any{"user_id": "ada"}, want: &auth.Identity{}},
		{name: "null values", claims: map[string]any{"sub": nil, "roles": nil, "user_id": nil, "permissions": nil}, want: &auth.Identity{}},
		{name: "permissions as string", claims: map[string]any{"permissions": "builds:write"}, want: &auth.Identity{}},
		{
			name:   "permissions with invalid entries",
			claims: map[string]any{"permissions": []any{"builds:write", 1.0, "Builds:write", "builds:admin", "builds", nil, map[string]any{"resource": "x"}, "*:read"}},
			want:   &auth.Identity{Permissions: []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}, {Resource: auth.AllResources, Access: auth.AccessRead}}},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			identity := identityFromClaims(testCase.claims)

			testCase.want.Active = true
			testCase.want.Claims = testCase.claims
			require.Equal(t, testCase.want, identity)
		})
	}
}
