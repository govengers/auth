package jwt

import (
	"fmt"
	"slices"

	"github.com/google/uuid"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/govengers/auth"
)

const (
	claimUserID      = "user_id"
	claimPermissions = "permissions"
)

// stringClaim maps a string field of an identity to the claim Sign writes and Verify reads.
type stringClaim struct {
	name  string
	field func(identity *auth.Identity) *string
}

// stringListClaim maps a string slice field of an identity to the JSON array claim Sign writes and Verify reads.
type stringListClaim struct {
	name  string
	field func(identity *auth.Identity) *[]string
}

var stringClaims = []stringClaim{
	{name: jwxjwt.SubjectKey, field: func(identity *auth.Identity) *string { return &identity.Subject }},
	{name: "provider", field: func(identity *auth.Identity) *string { return &identity.Provider }},
	{name: "preferred_username", field: func(identity *auth.Identity) *string { return &identity.Username }},
	{name: "name", field: func(identity *auth.Identity) *string { return &identity.Name }},
	{name: "email", field: func(identity *auth.Identity) *string { return &identity.Email }},
	{name: "picture", field: func(identity *auth.Identity) *string { return &identity.Picture }},
}

var stringListClaims = []stringListClaim{
	{name: "roles", field: func(identity *auth.Identity) *[]string { return &identity.Roles }},
	{name: "realm_roles", field: func(identity *auth.Identity) *[]string { return &identity.OIDCRoles }},
	{name: "client_roles", field: func(identity *auth.Identity) *[]string { return &identity.OIDCClientRoles }},
	{name: "groups", field: func(identity *auth.Identity) *[]string { return &identity.Groups }},
	{name: "teams", field: func(identity *auth.Identity) *[]string { return &identity.Teams }},
}

// uncopiedClaims are the keys of Identity.Claims that Sign never copies: registered and session-bound
// claims of the original ID token. The identity's own claims are skipped by ownedClaim as well, so a
// claim the identity left empty cannot come back from Claims (an IdP "roles" claim must not become
// application roles).
var uncopiedClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce", "at_hash", "c_hash", "auth_time", "sid", "azp"}

// identityClaims returns the claims Sign writes for identity, without the registered ones the Signer
// adds (iss, aud, iat, nbf, exp, jti). An invalid permission is an error.
func identityClaims(identity *auth.Identity) (map[string]any, error) {
	claims := make(map[string]any, len(identity.Claims)+len(stringClaims)+len(stringListClaims)+2)
	for name, value := range identity.Claims {
		if !ownedClaim(name) {
			claims[name] = value
		}
	}
	for _, claim := range stringClaims {
		if value := *claim.field(identity); value != "" {
			claims[claim.name] = value
		}
	}
	for _, claim := range stringListClaims {
		if values := *claim.field(identity); len(values) > 0 {
			claims[claim.name] = slices.Clone(values)
		}
	}
	if identity.UserID != uuid.Nil {
		claims[claimUserID] = identity.UserID.String()
	}
	if len(identity.Permissions) > 0 {
		permissions, err := permissionTexts(identity.Permissions)
		if err != nil {
			return nil, err
		}
		claims[claimPermissions] = permissions
	}
	return claims, nil
}

func permissionTexts(permissions []auth.Permission) ([]string, error) {
	texts := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		text, err := permission.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("permissions claim: %w", err)
		}
		texts = append(texts, string(text))
	}
	return texts, nil
}

func ownedClaim(name string) bool {
	return name == claimUserID || name == claimPermissions ||
		slices.Contains(uncopiedClaims, name) ||
		slices.ContainsFunc(stringClaims, func(claim stringClaim) bool { return claim.name == name }) ||
		slices.ContainsFunc(stringListClaims, func(claim stringListClaim) bool { return claim.name == name })
}

// identityFromClaims returns the identity a verified token carries. Claims of the wrong type are skipped.
func identityFromClaims(claims map[string]any) *auth.Identity {
	identity := &auth.Identity{Active: true, Claims: claims}
	for _, claim := range stringClaims {
		if value, ok := claims[claim.name].(string); ok {
			*claim.field(identity) = value
		}
	}
	for _, claim := range stringListClaims {
		*claim.field(identity) = stringList(claims[claim.name])
	}
	identity.UserID = userID(claims[claimUserID])
	identity.Permissions = permissions(claims[claimPermissions])
	return identity
}

// stringList returns the strings of a JSON array claim; non-string elements are skipped.
func stringList(value any) []string {
	elements, _ := value.([]any)
	var values []string
	for _, element := range elements {
		if text, ok := element.(string); ok {
			values = append(values, text)
		}
	}
	return values
}

// permissions returns the permissions of a JSON array claim of text forms; entries that are not strings
// or do not parse are dropped (fail closed per entry).
func permissions(value any) []auth.Permission {
	var parsed []auth.Permission
	for _, text := range stringList(value) {
		if permission, err := auth.ParsePermission(text); err == nil {
			parsed = append(parsed, permission)
		}
	}
	return parsed
}

func userID(value any) uuid.UUID {
	text, _ := value.(string)
	parsed, err := uuid.Parse(text)
	if err != nil {
		return uuid.Nil
	}
	return parsed
}
