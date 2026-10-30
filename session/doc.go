// Package session keeps server-side sessions for every provider of the module and authenticates
// requests with them.
//
// A Store issues sessions: the cookie carries 32 random bytes only, the Backend sees the SHA-256 of
// them and AES-256-GCM sealed values. Providers save the authenticated auth.Identity in the session;
// a Guard turns a request with such a session into a request with the identity in its context, or
// refuses it (401 JSON for APIs, 302 to a login URL for UIs), and re-validates identities through
// Refreshers at an interval. An Impersonator lets an identity act as another one in its own session,
// for a bounded time; it is the only way to start or stop an impersonation.
//
// The package works on net/http and context.Context only, never logs and never starts goroutines;
// expiry is lazy. Every component is safe for concurrent use after construction.
package session
