package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/govengers/auth"
)

func TestClaimMappers(t *testing.T) {
	testCases := []struct {
		name    string
		mapper  ClaimMapper
		claims  map[string]any
		profile Profile
	}{
		{
			name:    "default reads the standard claims",
			mapper:  DefaultClaimMapper,
			claims:  map[string]any{"preferred_username": "ada", "name": "Ada Lovelace", "email": "ada@example.com", "picture": "https://example.com/ada.png"},
			profile: Profile{Username: "ada", Name: "Ada Lovelace", Email: "ada@example.com", Picture: "https://example.com/ada.png"},
		},
		{name: "default with only an email", mapper: DefaultClaimMapper, claims: map[string]any{"email": "bob@example.com"}, profile: Profile{Email: "bob@example.com"}},
		{name: "default without claims", mapper: DefaultClaimMapper, claims: nil, profile: Profile{}},
		{name: "default skips non-string values", mapper: DefaultClaimMapper, claims: map[string]any{"name": 123, "preferred_username": true, "email": []any{"x"}}, profile: Profile{}},
		{
			name:    "google derives the username from the email",
			mapper:  GoogleClaimMapper,
			claims:  map[string]any{"name": "Ada Lovelace", "email": "ada@example.com", "picture": "https://example.com/ada.png", "preferred_username": "ignored"},
			profile: Profile{Username: "ada", Name: "Ada Lovelace", Email: "ada@example.com", Picture: "https://example.com/ada.png"},
		},
		{name: "google without email", mapper: GoogleClaimMapper, claims: map[string]any{"name": "Ada"}, profile: Profile{Name: "Ada"}},
		{name: "google with an email without @", mapper: GoogleClaimMapper, claims: map[string]any{"email": "ada"}, profile: Profile{Email: "ada"}},
		{name: "google without claims", mapper: GoogleClaimMapper, claims: map[string]any{}, profile: Profile{}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.profile, testCase.mapper(testCase.claims))
		})
	}
}

// Claims arrive from encoding/json, so every array is []any whatever the element type.
func TestTokenAuthorizationClaims(t *testing.T) {
	const client = "statics-scoring"
	testCases := []struct {
		name        string
		claims      map[string]any
		realmRoles  []string
		clientRoles []string
		groups      []string
	}{
		{
			name: "keycloak's usual shape",
			claims: map[string]any{
				"realm_access":    map[string]any{"roles": []any{"admin", "offline_access"}},
				"resource_access": map[string]any{client: map[string]any{"roles": []any{"scoring-admin"}}},
				"groups":          []any{"/statics-scoring/admins"},
			},
			realmRoles: []string{"admin", "offline_access"}, clientRoles: []string{"scoring-admin"}, groups: []string{"/statics-scoring/admins"},
		},
		{name: "roles of another client are not ours", claims: map[string]any{"resource_access": map[string]any{"other-app": map[string]any{"roles": []any{"admin"}}}}},
		{name: "non-string entries are skipped", claims: map[string]any{"realm_access": map[string]any{"roles": []any{42, "admin", nil}}}, realmRoles: []string{"admin"}},
		{name: "wrong shapes", claims: map[string]any{"realm_access": []any{"admin"}, "resource_access": "x", "groups": "/staff"}},
		{name: "none of the structures", claims: map[string]any{"sub": "abc"}},
		{name: "no claims", claims: nil},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.realmRoles, realmRoles(testCase.claims))
			require.Equal(t, testCase.clientRoles, clientRoles(testCase.claims, client))
			require.Equal(t, testCase.groups, groups(testCase.claims))
		})
	}
}

func TestRolesComeFromTheAccessTokenFirst(t *testing.T) {
	accessClaims := map[string]any{"realm_access": map[string]any{"roles": []any{"from-access"}}}
	identityClaims := map[string]any{
		"realm_access": map[string]any{"roles": []any{"from-id"}},
		"groups":       []any{"/from-id"},
	}

	require.Equal(t, []string{"from-access"}, firstNonEmpty(realmRoles(accessClaims), realmRoles(identityClaims)))
	require.Equal(t, []string{"/from-id"}, firstNonEmpty(groups(accessClaims), groups(identityClaims)))
	require.Nil(t, firstNonEmpty(groups(nil), groups(nil)))
}

func TestCheckEmailDomain(t *testing.T) {
	allowed := []string{"example.com"}
	testCases := []struct {
		name       string
		claims     map[string]any
		domains    []string
		wantReason string
	}{
		{name: "no restriction", claims: map[string]any{}, domains: nil},
		{name: "allowed", claims: map[string]any{"email": "ada@EXAMPLE.com", "email_verified": true}, domains: allowed},
		{name: "not verified", claims: map[string]any{"email": "ada@example.com", "email_verified": false}, domains: allowed, wantReason: "email not verified"},
		{name: "verified as a string", claims: map[string]any{"email": "ada@example.com", "email_verified": "true"}, domains: allowed, wantReason: "email not verified"},
		{name: "other domain", claims: map[string]any{"email": "ada@example.org", "email_verified": true}, domains: allowed, wantReason: "email domain not allowed"},
		{name: "two @", claims: map[string]any{"email": "ada@evil.example@example.com", "email_verified": true}, domains: allowed, wantReason: "email domain not allowed"},
		{name: "no email", claims: map[string]any{"email_verified": true}, domains: allowed, wantReason: "email domain not allowed"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := checkEmailDomain(testCase.claims, testCase.domains)

			if testCase.wantReason == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, auth.ErrForbidden)
			require.ErrorContains(t, err, testCase.wantReason)
		})
	}
}

func TestAuthStyle(t *testing.T) {
	testCases := []struct {
		name    string
		methods []string
		want    oauth2.AuthStyle
	}{
		{name: "nothing listed: the OIDC default", methods: nil, want: oauth2.AuthStyleInHeader},
		{name: "both", methods: []string{"client_secret_post", "client_secret_basic"}, want: oauth2.AuthStyleInHeader},
		{name: "post only", methods: []string{"client_secret_post", "private_key_jwt"}, want: oauth2.AuthStyleInParams},
		{name: "neither", methods: []string{"private_key_jwt"}, want: oauth2.AuthStyleInHeader},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, authenticationStyle(testCase.methods))
		})
	}
}
