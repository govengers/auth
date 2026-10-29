// Package jwt mints and verifies the RS512 JSON Web Tokens that carry an auth.Identity from the
// forward-auth server to the backends behind it.
//
// A Signer turns an identity into a short-lived token and serves its public key as a JWKS. A Verifier
// checks such tokens against that JWKS and turns them back into an identity, as a function (Verify) or
// as net/http middleware (Middleware). Both are safe for concurrent use.
//
// Claims of a token (a field is omitted when empty):
//
//	iss, aud                                         SignerOptions.Issuer, SignerOptions.Audience
//	iat, nbf, exp, jti                               now, now - 30 s, now + Lifetime, random UUID
//	sub, provider, user_id                           Identity.Subject, Provider, UserID (omitted for uuid.Nil)
//	preferred_username, name, email, picture         Identity.Username, Name, Email, Picture
//	roles, realm_roles, client_roles, groups, teams  Identity.Roles, OIDCRoles, OIDCClientRoles, Groups, Teams (JSON arrays)
//	any other key of Identity.Claims                 copied, except nonce, at_hash, c_hash, auth_time, sid, azp
//
// Verify reads the same claims back, sets Active and puts all claims of the token into Identity.Claims.
// Attributes, Data and Impersonator are not carried.
//
// The package never logs and starts no goroutines: the Verifier refreshes its keys lazily inside Verify.
package jwt
