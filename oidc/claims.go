package oidc

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/govengers/auth"
)

// Profile is what a ClaimMapper reads from ID token claims.
type Profile struct {
	Username, Name, Email, Picture string
}

// ClaimMapper is a pure function from ID token claims to a Profile. It must not keep or change the map.
type ClaimMapper func(claims map[string]any) Profile

// DefaultClaimMapper reads preferred_username, name, email and picture; a claim that is missing or not a
// string stays empty. Fits Keycloak and most standard providers.
func DefaultClaimMapper(claims map[string]any) Profile {
	return Profile{
		Username: stringClaim(claims, "preferred_username"),
		Name:     stringClaim(claims, "name"),
		Email:    stringClaim(claims, "email"),
		Picture:  stringClaim(claims, "picture"),
	}
}

// GoogleClaimMapper reads name, email and picture; Username is the part of email before "@" (Google
// sends no preferred_username).
func GoogleClaimMapper(claims map[string]any) Profile {
	email := stringClaim(claims, "email")
	username, _, found := strings.Cut(email, "@")
	if !found {
		username = ""
	}
	return Profile{
		Username: username,
		Name:     stringClaim(claims, "name"),
		Email:    email,
		Picture:  stringClaim(claims, "picture"),
	}
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

// Keycloak puts realm_access, resource_access and groups into the access token by default; the ID token
// carries them only when each mapper has "Add to ID token" switched on. So the access token is read
// first and the ID token second.

// realmRoles reads Keycloak's realm_access.roles.
func realmRoles(claims map[string]any) []string {
	realmAccess, _ := claims["realm_access"].(map[string]any)
	return stringsClaim(realmAccess, "roles")
}

// clientRoles reads Keycloak's resource_access.<clientID>.roles.
func clientRoles(claims map[string]any, clientID string) []string {
	resourceAccess, _ := claims["resource_access"].(map[string]any)
	client, _ := resourceAccess[clientID].(map[string]any)
	return stringsClaim(client, "roles")
}

// groups reads the groups claim; full paths or bare names, depending on the IdP's mapper.
func groups(claims map[string]any) []string {
	return stringsClaim(claims, "groups")
}

// stringsClaim reads a JSON array of strings, which decoded claims hold as []any; other entries are
// skipped. nil when there is none.
func stringsClaim(claims map[string]any, name string) []string {
	values, _ := claims[name].([]any)
	var result []string
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func firstNonEmpty(candidates ...[]string) []string {
	for _, candidate := range candidates {
		if len(candidate) > 0 {
			return candidate
		}
	}
	return nil
}

// checkEmailDomain allows any login when allowedDomains is empty. Otherwise the ID token must carry
// email_verified true and an email whose domain (ASCII lower-cased; a non-ASCII domain never matches) is
// one of allowedDomains (lower-case ASCII).
func checkEmailDomain(claims map[string]any, allowedDomains []string) error {
	if len(allowedDomains) == 0 {
		return nil
	}
	if verified, _ := claims["email_verified"].(bool); !verified {
		return &auth.Error{Kind: auth.ErrForbidden, Reason: "email not verified"}
	}
	_, domain, found := strings.Cut(stringClaim(claims, "email"), "@")
	domain, ascii := asciiLower(domain)
	if !found || !ascii || !slices.Contains(allowedDomains, domain) {
		return &auth.Error{Kind: auth.ErrForbidden, Reason: "email domain not allowed"}
	}
	return nil
}

// asciiLower lower-cases the ASCII letters of value; false when value has a non-ASCII byte. strings.ToLower
// alone also folds Unicode (the Kelvin sign U+212A becomes "k"), so another domain could match an allowed one.
func asciiLower(value string) (string, bool) {
	for index := range len(value) {
		if value[index] >= utf8.RuneSelf {
			return "", false
		}
	}
	return strings.ToLower(value), true
}
