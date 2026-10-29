package auth

import (
	"maps"
	"slices"

	"github.com/google/uuid"
)

// RoleAdmin is the application role that authorization.IsAdmin requires. The GitHub provider grants it to AdminTeams members.
const RoleAdmin = "admin"

// Identity is who a request acts as, whichever provider authenticated it. It is a value type:
// providers build it, hooks may return a modified copy, the session stores it as JSON (the tags are a
// persistence format; never rename them). An Identity is not synchronized: share it read-only, or Clone it.
type Identity struct {
	Provider        string              `json:"provider"`           // provider instance: "password", "github", "apikey" or an OIDC provider Name; a verified JWT keeps the provider it was signed for
	Subject         string              `json:"subject"`            // stable ID at the provider: OIDC sub, GitHub numeric user ID, password user UUID, API key name
	UserID          uuid.UUID           `json:"userId"`             // application user ID; uuid.Nil until the password provider or an OnLogin hook sets it
	Username        string              `json:"username,omitempty"` // preferred_username, GitHub login, password username, API key name
	Name            string              `json:"name,omitempty"`
	Email           string              `json:"email,omitempty"`
	Picture         string              `json:"picture,omitempty"`         // OIDC picture claim, GitHub avatar_url
	Active          bool                `json:"active"`                    // providers set true at login; hooks may set false
	Roles           []string            `json:"roles,omitempty"`           // application roles (RoleAdmin)
	OIDCRoles       []string            `json:"oidcRoles,omitempty"`       // Keycloak realm roles
	OIDCClientRoles []string            `json:"oidcClientRoles,omitempty"` // Keycloak client roles of the configured client
	Groups          []string            `json:"groups,omitempty"`          // OIDC groups (path or name, per IdP mapper)
	Teams           []string            `json:"teams,omitempty"`           // GitHub "org/team-slug", lower-case
	Attributes      map[string][]string `json:"attributes,omitempty"`      // Keycloak user attributes
	Claims          map[string]any      `json:"claims,omitempty"`          // OIDC ID token claims, or all claims of a verified JWT
	Data            map[string]any      `json:"data,omitempty"`            // application data from hooks and resolvers; JSON round trip (numbers become float64)
	Impersonator    *Identity           `json:"impersonator,omitempty"`    // the real identity while it impersonates this one; nil otherwise
}

// Real returns the identity that authenticated: the Impersonator while impersonating, the receiver otherwise. Nil-safe (nil in, nil out).
func (i *Identity) Real() *Identity {
	if i == nil || i.Impersonator == nil {
		return i
	}
	return i.Impersonator
}

// Clone returns a deep copy: slices, Attributes and the Impersonator chain are copied; Claims and Data are copied one level (values shared). Nil-safe.
func (i *Identity) Clone() *Identity {
	if i == nil {
		return nil
	}
	clone := *i
	clone.Roles = slices.Clone(i.Roles)
	clone.OIDCRoles = slices.Clone(i.OIDCRoles)
	clone.OIDCClientRoles = slices.Clone(i.OIDCClientRoles)
	clone.Groups = slices.Clone(i.Groups)
	clone.Teams = slices.Clone(i.Teams)
	clone.Attributes = cloneAttributes(i.Attributes)
	clone.Claims = maps.Clone(i.Claims)
	clone.Data = maps.Clone(i.Data)
	clone.Impersonator = i.Impersonator.Clone()
	return &clone
}

func cloneAttributes(attributes map[string][]string) map[string][]string {
	if attributes == nil {
		return nil
	}
	clone := make(map[string][]string, len(attributes))
	for name, values := range attributes {
		clone[name] = slices.Clone(values)
	}
	return clone
}
