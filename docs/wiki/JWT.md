# JWT

RS512 tokens that carry an `auth.Identity` from a signer (the forward-auth image, or your own `jwt.Signer`) to backends. A backend verifies them with `jwt.Verifier` against the signer's JWKS and gets the identity without sessions.

## Backend verification

Tested ([jwt/example_test.go](../../jwt/example_test.go), `ExampleVerifier`):

```go
	verifier, err := jwt.NewVerifier(context.Background(), &jwt.VerifierOptions{JWKSURL: forwardAuth.URL, Issuer: "https://auth.example.com"})
	if err != nil {
		fmt.Println(err)
		return
	}
	api := verifier.Middleware()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := auth.IdentityFrom(request.Context())
```

- `JWKSURL`: the signer's JWKS, e.g. `http://forwardauth:8080/auth/jwks` (an internal address is fine). `NewVerifier` fetches it once and fails fast.
- `Issuer`: the signer's issuer; for the image `JWT_ISSUER`, default its `EXTERNAL_URL`. `Audience` optional.
- `Middleware()` reads `Authorization: Bearer <token>` (`HeaderName` to change; scheme in any case, spaces around the token ignored) and answers 401 `unauthenticated` (missing) or `invalid_token` (invalid), with `WWW-Authenticate: Bearer`. Why a token was refused (expired, issuer mismatch, ...) is in the outcome's Reason, never token content. `Verify(ctx, token)` is the same check as a function.
- `Verify` checks the signature (with the JWKS key the token's `kid` names, under that key's algorithm), `iss`, `aud`, `exp` (required), `nbf` and `iat` (30 s skew). `sub` becomes `Subject`, `preferred_username` `Username`; `provider`, `user_id`, `name`, `email`, `picture`, `roles`, `realm_roles`, `client_roles`, `groups`, `teams` fill the matching fields, `permissions` fills `Permissions` (entries that do not parse are dropped).
- On gin: `ginadapter.Middleware(verifier.Middleware())`, then `ginadapter.Require(...)`.
- The identity comes back `Active`, with `Roles`, `OIDCRoles`, `OIDCClientRoles`, `Groups`, `Teams`, `Permissions` and every claim in `Claims`; `Attributes`, `Data` and `Impersonator` are not carried. Claim table: `go doc github.com/govengers/auth/jwt` ([jwt/doc.go](../../jwt/doc.go)).

## Signing

`jwt.NewSigner(&jwt.SignerOptions{PrivateKey, Issuer, Audience, Lifetime})` with a PEM RSA key of at least 2048 bits (no generated fallback: every replica must load the same key). `Sign(identity)` mints a token (default lifetime 5 min, key ID = RFC 7638 thumbprint); `JWKSHandler()` serves the public key. Tested: `ExampleSigner` in [jwt/example_test.go](../../jwt/example_test.go).

## Gotchas

- `Sign` refuses an inactive identity (403): a verified token always yields an active one.
- Do not mount `apikey` middleware in front of the verifier: both read `Authorization: Bearer`, and `apikey` refuses foreign bearer tokens with 401.
- JWKS refetch: after `RefreshInterval` (default 1 h, at least 1 min) or for an unknown key ID, at most once a minute, detached from the request that triggered it and bounded by 10 s. While it runs, tokens with a known key ID verify with the current keys; tokens with an unknown one wait for it, at most until their own request ends. A failed refetch keeps the old keys; a token with an unknown key ID then gets 500. No token cache, no goroutine.
- Only RSA keys with an RSA signature `alg` (RS256/384/512, PS256/384/512), a `kid` and use `sig` (or none) count; other keys and entries that do not parse are ignored. A JWKS without a usable key, that is not a JSON JWK set or larger than 1 MiB fails `NewVerifier`. Errors name the JWKS URL without credentials and query and never repeat the answer's bytes.
- Trust the token, never identity headers a client could set; see the [Traefik settings](Forward-Auth-Configuration.md#traefik-settings).

Source: [jwt/](../../jwt/) ([signer.go](../../jwt/signer.go), [verifier.go](../../jwt/verifier.go), [claims.go](../../jwt/claims.go)).
