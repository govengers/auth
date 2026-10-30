package hook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

func TestRunOnLogin(t *testing.T) {
	identity := &auth.Identity{Provider: "github", Subject: "1"}
	mapped := &auth.Identity{Provider: "github", Subject: "1", Roles: []string{auth.RoleAdmin}}
	refusal := &auth.Error{Kind: auth.ErrForbidden, Reason: "inactive user"}

	t.Run("no hook", func(t *testing.T) {
		result, err := RunOnLogin(t.Context(), nil, identity)
		require.NoError(t, err)
		require.Same(t, identity, result)
	})
	t.Run("maps", func(t *testing.T) {
		var received *auth.Identity
		result, err := RunOnLogin(t.Context(), func(_ context.Context, argument *auth.Identity) (*auth.Identity, error) {
			received = argument
			return mapped, nil
		}, identity)
		require.NoError(t, err)
		require.Same(t, identity, received)
		require.Same(t, mapped, result)
	})
	t.Run("refusal keeps its kind", func(t *testing.T) {
		result, err := RunOnLogin(t.Context(), func(context.Context, *auth.Identity) (*auth.Identity, error) { return nil, refusal }, identity)
		require.Nil(t, result)
		require.ErrorIs(t, err, auth.ErrForbidden)
		require.ErrorIs(t, err, refusal)
	})
	t.Run("no identity", func(t *testing.T) {
		result, err := RunOnLogin(t.Context(), func(context.Context, *auth.Identity) (*auth.Identity, error) {
			return nil, nil //nolint:nilnil // the misbehaving hook under test
		}, identity)
		require.Nil(t, result)
		require.EqualError(t, err, "OnLogin returned no identity")
	})
}
