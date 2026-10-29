package auth

import "context"

// Hook maps an identity. OnLogin hooks run after the provider authenticated the user and before a
// session exists: the returned identity is stored; an error aborts the login (an *Error answers with
// its status, anything else 500) and no session is created. Hooks must not mutate the argument;
// return identity.Clone() with changes. Providers may call a hook from concurrent requests.
type Hook func(ctx context.Context, identity *Identity) (*Identity, error)

// LogoutHook runs after a session was ended (all providers, RP-initiated and front-channel logout).
// It cannot fail the logout and has no access to the response. Providers may call it from concurrent
// requests.
type LogoutHook func(ctx context.Context, identity *Identity)
