// Package oidc is the OpenID Connect provider: authorization code flow with PKCE (S256) and nonce,
// state bound to the server-side session, RP-initiated logout through the discovered
// end_session_endpoint and front-channel logout.
//
// A successful callback stores an auth.Identity in the shared session.Store, so the one session.Guard
// of the application authenticates OIDC users like every other provider's. Several providers (one per
// IdP, distinct names) share one Store. Roles and groups come from the access token, else from the ID
// token (Keycloak's realm_access, resource_access and groups claims); set OnLogin to a
// keycloak.Client's Enrich to read them from the Keycloak Admin API instead.
//
// The package never logs; outcomes go to the optional auth.Observer.
package oidc
