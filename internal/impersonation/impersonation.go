// Package impersonation writes a refreshed real identity back into an identity that may be
// impersonating another one. Its functions are pure and safe for concurrent use.
package impersonation

import "github.com/govengers/auth"

// WithReal returns identity with its real identity (identity.Real()) replaced by refreshed: while
// impersonating a copy of identity whose Impersonator is refreshed, otherwise refreshed itself. Neither
// input is modified, and refreshed is not copied.
func WithReal(identity, refreshed *auth.Identity) *auth.Identity {
	if identity.Impersonator == nil {
		return refreshed
	}
	impersonated := identity.Clone()
	impersonated.Impersonator = refreshed
	return impersonated
}
