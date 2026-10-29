package auth

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func fullIdentity() *Identity {
	return &Identity{
		Provider:        "keycloak",
		Subject:         "subject-1",
		UserID:          uuid.MustParse("6f1c2a52-6c43-4c5e-9d3a-0f3d1c2b4a5e"),
		Username:        "ada",
		Name:            "Ada Lovelace",
		Email:           "ada@example.com",
		Picture:         "https://example.com/ada.png",
		Active:          true,
		Roles:           []string{RoleAdmin},
		OIDCRoles:       []string{"realm-role"},
		OIDCClientRoles: []string{"client-role"},
		Groups:          []string{"/engineering"},
		Teams:           []string{"org/team"},
		Attributes:      map[string][]string{"department": {"research"}},
		Claims:          map[string]any{"sub": "subject-1"},
		Data:            map[string]any{"tenant": "a"},
		Impersonator:    &Identity{Provider: "password", Subject: "admin-1", Roles: []string{RoleAdmin}},
	}
}

func TestIdentityContextRoundTrip(t *testing.T) {
	identity := fullIdentity()

	ctx := WithIdentity(t.Context(), identity)

	require.Same(t, identity, IdentityFrom(ctx))
}

func TestIdentityFromWithoutIdentity(t *testing.T) {
	require.Nil(t, IdentityFrom(t.Context()))
	require.Nil(t, IdentityFrom(WithIdentity(t.Context(), nil)))
}

func TestIdentityReal(t *testing.T) {
	impersonator := &Identity{Subject: "admin"}
	impersonated := &Identity{Subject: "user", Impersonator: impersonator}
	plain := &Identity{Subject: "user"}
	var nilIdentity *Identity

	require.Same(t, impersonator, impersonated.Real())
	require.Same(t, plain, plain.Real())
	require.Nil(t, nilIdentity.Real())
}

func TestIdentityClone(t *testing.T) {
	original := fullIdentity()

	clone := original.Clone()

	require.Equal(t, original, clone)
	require.NotSame(t, original, clone)
	require.NotSame(t, original.Impersonator, clone.Impersonator)

	clone.Roles[0] = "changed"
	clone.OIDCRoles[0] = "changed"
	clone.OIDCClientRoles[0] = "changed"
	clone.Groups[0] = "changed"
	clone.Teams[0] = "changed"
	clone.Attributes["department"][0] = "changed"
	clone.Attributes["added"] = []string{"x"}
	clone.Claims["added"] = "x"
	clone.Data["added"] = "x"
	clone.Impersonator.Roles[0] = "changed"

	require.Equal(t, fullIdentity(), original)
}

func TestIdentityCloneKeepsNilFields(t *testing.T) {
	var nilIdentity *Identity
	require.Nil(t, nilIdentity.Clone())

	clone := (&Identity{Subject: "s"}).Clone()

	require.Equal(t, &Identity{Subject: "s"}, clone)
	require.Nil(t, clone.Roles)
	require.Nil(t, clone.Attributes)
	require.Nil(t, clone.Claims)
	require.Nil(t, clone.Impersonator)
}
