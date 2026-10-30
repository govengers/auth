// Package sessiontest sets up session states for the tests of packages that build on package session.
package sessiontest

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/session"
)

// Impersonate lets the identity of the session request carries impersonate target, as an application's
// route would, and returns the impersonating identity. The impersonator admits any active identities.
func Impersonate(t *testing.T, store *session.Store, request *http.Request, target *auth.Identity) *auth.Identity {
	t.Helper()
	impersonated, err := newImpersonator(t, store, target).Start(withStoredIdentity(t, store, request), target.Subject)
	require.NoError(t, err)
	return impersonated
}

// StopImpersonating ends the impersonation of the session request carries, as an application's route
// would, and returns the impersonator's identity.
func StopImpersonating(t *testing.T, store *session.Store, request *http.Request) *auth.Identity {
	t.Helper()
	impersonator, err := newImpersonator(t, store, nil).Stop(withStoredIdentity(t, store, request))
	require.NoError(t, err)
	return impersonator
}

func newImpersonator(t *testing.T, store *session.Store, target *auth.Identity) *session.Impersonator {
	t.Helper()
	guard, err := session.NewGuard(&session.GuardOptions{Store: store})
	require.NoError(t, err)
	impersonator, err := session.NewImpersonator(&session.ImpersonatorOptions{
		Guard:  guard,
		Load:   func(context.Context, string) (*auth.Identity, error) { return target.Clone(), nil },
		Actor:  authorization.IsAuthenticated(),
		Target: authorization.IsAuthenticated(),
	})
	require.NoError(t, err)
	return impersonator
}

// withStoredIdentity returns request with the identity of its session in its context, as the Guard puts it.
func withStoredIdentity(t *testing.T, store *session.Store, request *http.Request) *http.Request {
	t.Helper()
	current, err := store.Open(request)
	require.NoError(t, err)
	identity, err := current.Identity(t.Context())
	require.NoError(t, err)
	return request.WithContext(auth.WithIdentity(request.Context(), identity))
}
