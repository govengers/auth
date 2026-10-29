package impersonation

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

func TestWithReal(t *testing.T) {
	refreshed := &auth.Identity{Provider: "github", Subject: "1", Teams: []string{"acme/new"}}

	t.Run("not impersonating", func(t *testing.T) {
		stored := &auth.Identity{Provider: "github", Subject: "1"}
		require.Same(t, refreshed, WithReal(stored, refreshed))
	})
	t.Run("impersonating", func(t *testing.T) {
		stored := &auth.Identity{Provider: "password", Subject: "user", Roles: []string{"viewer"}, Impersonator: &auth.Identity{Provider: "github", Subject: "1"}}
		before := stored.Clone()

		updated := WithReal(stored, refreshed)

		require.Equal(t, "user", updated.Subject)
		require.Same(t, refreshed, updated.Impersonator)
		require.Equal(t, before, stored)
		updated.Roles[0] = "changed"
		require.Equal(t, []string{"viewer"}, stored.Roles, "the impersonated identity is a copy")
	})
}
