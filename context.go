package auth

import (
	"context"
	"time"
)

type identityKey struct{}

type impersonationEndsAtKey struct{}

// WithIdentity returns a copy of ctx carrying identity.
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

// IdentityFrom returns the identity in ctx, or nil.
func IdentityFrom(ctx context.Context) *Identity {
	identity, _ := ctx.Value(identityKey{}).(*Identity)
	return identity
}

// WithImpersonationEndsAt returns a copy of ctx carrying when the impersonation of its identity ends. The
// session Guard sets it next to an impersonating identity; IdentityHandler answers it.
func WithImpersonationEndsAt(ctx context.Context, endsAt time.Time) context.Context {
	return context.WithValue(ctx, impersonationEndsAtKey{}, endsAt)
}

// ImpersonationEndsAtFrom returns when the impersonation of the identity in ctx ends; zero when ctx carries
// no end (no impersonation, or an identity that did not come from a session, such as a JWT's).
func ImpersonationEndsAtFrom(ctx context.Context) time.Time {
	endsAt, _ := ctx.Value(impersonationEndsAtKey{}).(time.Time)
	return endsAt
}
