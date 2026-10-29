// Package auth holds what every provider of the module shares: the Identity a request acts as, the
// context helpers that carry it, the refusal errors with their one JSON response shape, the outcomes
// providers report to an optional Observer, the login and logout hook types, and the Route type
// providers return their endpoints as.
//
// The package works on net/http and context.Context only, never logs and never starts goroutines.
// Its functions and handlers are safe for concurrent use; an Identity is shared read-only or cloned.
package auth
