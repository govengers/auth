package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePermission(t *testing.T) {
	testCases := []struct {
		name      string
		text      string
		want      Permission
		wantError bool
	}{
		{name: "resource read", text: "builds:read", want: Permission{Resource: "builds", Access: AccessRead}},
		{name: "resource write", text: "builds:write", want: Permission{Resource: "builds", Access: AccessWrite}},
		{name: "all resources", text: "*:read", want: Permission{Resource: AllResources, Access: AccessRead}},
		{name: "digits dots dashes underscores", text: "v2.build-logs_x:write", want: Permission{Resource: "v2.build-logs_x", Access: AccessWrite}},
		{name: "longest resource", text: strings.Repeat("a", 64) + ":read", want: Permission{Resource: strings.Repeat("a", 64), Access: AccessRead}},
		{name: "empty", text: "", wantError: true},
		{name: "no separator", text: "builds", wantError: true},
		{name: "empty resource", text: ":read", wantError: true},
		{name: "empty access", text: "builds:", wantError: true},
		{name: "unknown access", text: "builds:admin", wantError: true},
		{name: "upper-case access", text: "builds:READ", wantError: true},
		{name: "upper-case resource", text: "Builds:read", wantError: true},
		{name: "resource starting with a dot", text: ".builds:read", wantError: true},
		{name: "resource with a slash", text: "builds/1:read", wantError: true},
		{name: "resource with a space", text: "build logs:read", wantError: true},
		{name: "partial wildcard", text: "build*:read", wantError: true},
		{name: "second separator", text: "builds:read:write", wantError: true},
		{name: "resource too long", text: strings.Repeat("a", 65) + ":read", wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			permission, err := ParsePermission(testCase.text)
			if testCase.wantError {
				require.Error(t, err)
				require.Zero(t, permission)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.want, permission)
			require.Equal(t, testCase.text, permission.String())
		})
	}
}

func TestPermissionValidate(t *testing.T) {
	require.NoError(t, Permission{Resource: "builds", Access: AccessRead}.Validate())
	require.ErrorContains(t, Permission{Resource: "", Access: AccessRead}.Validate(), "resource")
	require.ErrorContains(t, Permission{Resource: "builds", Access: "delete"}.Validate(), "access")
}

func TestPermissionGrants(t *testing.T) {
	buildsRead := Permission{Resource: "builds", Access: AccessRead}
	buildsWrite := Permission{Resource: "builds", Access: AccessWrite}
	allRead := Permission{Resource: AllResources, Access: AccessRead}
	allWrite := Permission{Resource: AllResources, Access: AccessWrite}

	testCases := []struct {
		name       string
		permission Permission
		resource   string
		access     Access
		want       bool
	}{
		{name: "read grants read", permission: buildsRead, resource: "builds", access: AccessRead, want: true},
		{name: "read does not grant write", permission: buildsRead, resource: "builds", access: AccessWrite, want: false},
		{name: "write grants write", permission: buildsWrite, resource: "builds", access: AccessWrite, want: true},
		{name: "write grants read", permission: buildsWrite, resource: "builds", access: AccessRead, want: true},
		{name: "other resource", permission: buildsWrite, resource: "deployments", access: AccessRead, want: false},
		{name: "all resources read grants read", permission: allRead, resource: "deployments", access: AccessRead, want: true},
		{name: "all resources read does not grant write", permission: allRead, resource: "deployments", access: AccessWrite, want: false},
		{name: "all resources write grants write", permission: allWrite, resource: "deployments", access: AccessWrite, want: true},
		{name: "all resources required needs the wildcard", permission: buildsWrite, resource: AllResources, access: AccessRead, want: false},
		{name: "wildcard satisfies all resources", permission: allRead, resource: AllResources, access: AccessRead, want: true},
		{name: "empty resource fails closed", permission: allWrite, resource: "", access: AccessRead, want: false},
		{name: "invalid resource fails closed", permission: allWrite, resource: "Builds", access: AccessRead, want: false},
		{name: "empty access fails closed", permission: allWrite, resource: "builds", access: "", want: false},
		{name: "unknown access fails closed", permission: allWrite, resource: "builds", access: "admin", want: false},
		{name: "invalid permission grants nothing", permission: Permission{Resource: "builds", Access: "admin"}, resource: "builds", access: AccessRead, want: false},
		{name: "zero permission grants nothing", permission: Permission{}, resource: "builds", access: AccessRead, want: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.permission.Grants(testCase.resource, testCase.access))
		})
	}
}

func TestIdentityPermits(t *testing.T) {
	buildsRead := Permission{Resource: "builds", Access: AccessRead}
	deploymentsWrite := Permission{Resource: "deployments", Access: AccessWrite}
	allRead := Permission{Resource: AllResources, Access: AccessRead}

	testCases := []struct {
		name     string
		identity *Identity
		resource string
		access   Access
		want     bool
	}{
		{name: "nil identity", identity: nil, resource: "builds", access: AccessRead, want: false},
		{name: "no permissions", identity: &Identity{Active: true}, resource: "builds", access: AccessRead, want: false},
		{name: "matching permission", identity: &Identity{Permissions: []Permission{buildsRead}}, resource: "builds", access: AccessRead, want: true},
		{name: "second permission matches", identity: &Identity{Permissions: []Permission{buildsRead, deploymentsWrite}}, resource: "deployments", access: AccessRead, want: true},
		{name: "read does not grant write", identity: &Identity{Permissions: []Permission{buildsRead}}, resource: "builds", access: AccessWrite, want: false},
		{name: "wildcard read", identity: &Identity{Permissions: []Permission{allRead}}, resource: "deployments", access: AccessRead, want: true},
		{name: "wildcard read does not grant write", identity: &Identity{Permissions: []Permission{allRead, buildsRead}}, resource: "deployments", access: AccessWrite, want: false},
		{name: "invalid permission skipped", identity: &Identity{Permissions: []Permission{{Resource: "builds", Access: "admin"}, buildsRead}}, resource: "builds", access: AccessRead, want: true},
		{name: "unknown access fails closed", identity: &Identity{Permissions: []Permission{deploymentsWrite}}, resource: "deployments", access: "delete", want: false},
		{name: "inactive identity still permits (callers check Active)", identity: &Identity{Active: false, Permissions: []Permission{buildsRead}}, resource: "builds", access: AccessRead, want: true},
		{name: "impersonator permissions do not count", identity: &Identity{Impersonator: &Identity{Permissions: []Permission{allRead}}}, resource: "builds", access: AccessRead, want: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.identity.Permits(testCase.resource, testCase.access))
		})
	}
}

func TestPermissionJSON(t *testing.T) {
	identity := &Identity{
		Provider:    "apikey",
		Subject:     "ci",
		Active:      true,
		Permissions: []Permission{{Resource: "builds", Access: AccessWrite}, {Resource: AllResources, Access: AccessRead}},
	}

	encoded, err := json.Marshal(identity)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"permissions":["builds:write","*:read"]`)

	var decoded Identity
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, identity, &decoded)
}

func TestPermissionJSONRejectsInvalidPermissions(t *testing.T) {
	_, err := json.Marshal(&Identity{Permissions: []Permission{{Resource: "builds", Access: "admin"}}})
	require.Error(t, err)

	var decoded Identity
	require.Error(t, json.Unmarshal([]byte(`{"permissions":["builds:admin"]}`), &decoded))
}

func TestAccessForMethod(t *testing.T) {
	testCases := []struct {
		method string
		want   Access
	}{
		{method: http.MethodGet, want: AccessRead},
		{method: http.MethodHead, want: AccessRead},
		{method: http.MethodOptions, want: AccessRead},
		{method: http.MethodPost, want: AccessWrite},
		{method: http.MethodPut, want: AccessWrite},
		{method: http.MethodPatch, want: AccessWrite},
		{method: http.MethodDelete, want: AccessWrite},
		{method: "get", want: AccessWrite},
		{method: "", want: AccessWrite},
	}
	for _, testCase := range testCases {
		t.Run(testCase.method, func(t *testing.T) {
			require.Equal(t, testCase.want, AccessForMethod(testCase.method))
		})
	}
}
