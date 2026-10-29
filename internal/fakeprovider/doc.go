// Package fakeprovider holds fake identity providers for tests and the end-to-end stack: an OpenID
// Connect issuer that can also answer as a Keycloak Admin API, and a GitHub OAuth server. The fakes
// are strict on purpose (a client that skips PKCE, state or nonce fails) and log in one configured
// user without a login page. Test support only: never use them to protect anything.
package fakeprovider
