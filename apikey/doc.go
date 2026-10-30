// Package apikey authenticates requests that present an API key, independent of any login provider.
// Static keys are configured with a name and a secret; keys issued by the application are looked up by
// a Resolver. Either way a valid key puts an auth.Identity into the request context.
//
// The Authenticator never logs and never starts goroutines. It is safe for concurrent use.
package apikey
