package auth

import "context"

type identityKey struct{}

// WithIdentity returns a copy of ctx carrying identity.
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

// IdentityFrom returns the identity in ctx, or nil.
func IdentityFrom(ctx context.Context) *Identity {
	identity, _ := ctx.Value(identityKey{}).(*Identity)
	return identity
}
