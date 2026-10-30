# auth

[![CI](https://github.com/govengers/auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![unit tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/unit-tests.json)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![e2e tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/e2e-tests.json)](test/e2e)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/coverage.json)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/govengers/auth.svg)](https://pkg.go.dev/github.com/govengers/auth)
[![License](https://img.shields.io/github/license/govengers/auth)](LICENSE)

Authentication and authorization for Go services, plus a forward-auth proxy image for Traefik.

Every provider (password, OIDC incl. Keycloak, GitHub OAuth, API key, JWT) produces the same `auth.Identity`. Redirect and password logins store it in one server-side session (the cookie carries a random ID only). One `session.Guard` turns a request with a session into a request with an identity in its `context.Context`, or refuses it: 401 JSON for APIs, 302 to the login URL for UIs. Authorization is a plain `func(context.Context) error` over that identity: roles, groups, teams and resource permissions (`builds:write`). The core packages are `net/http` only; gin, the wide-event logger and Prometheus stay in adapter packages. It replaces `mxcd/go-basicauth`, `mxcd/oidc-fwd-auth` and `mxcd/github-fwd-auth` ([migration guide](docs/migration.md)).

## Installation

```bash
go get github.com/govengers/auth@v1
```

One module, one package per provider. A program that imports `password` compiles neither gin, go-oidc nor Redis.

| Package | Purpose | Heavy dependency |
|---|---|---|
| `auth` | `Identity`, `Permission`, context helpers, `Error` and the one JSON error shape, `Observer`, `Hook`, `Route`, `IdentityHandler` | - |
| `session` | server-side sessions: `Store`, `Backend`, `MemoryBackend`, `Guard` (`RequireAPI`, `RequireUI`), `Refresher`, `ParseKey` | - |
| `session/redisbackend` | `session.Backend` on Redis (client, sentinel or cluster) | go-redis |
| `password` | username/email + password (Argon2id), TOTP with backup codes, registration, legacy bcrypt upgrade; you implement `Storage` | x/crypto, otp |
| `oidc` | OIDC code flow with PKCE and nonce, RP-initiated and front-channel logout, claim mappers (Google) | go-oidc |
| `oidc/keycloak` | Keycloak Admin API enrichment (roles, groups, attributes, required roles) as an `OnLogin` hook | - |
| `github` | GitHub OAuth with PKCE, allowed/admin/relevant teams, token kept server-side, team refresh | - |
| `apikey` | static hashed API keys with roles and permissions, and a resolver for keys you issue | - |
| `jwt` | RS512 `Signer` with JWKS endpoint, JWKS `Verifier` with middleware | jwx v3 |
| `authorization` | `Check` combinators (`All`, `Any`, `Not`, `Real`) and primitives (`IsAdmin`, `HasRole`, `HasPermission`, ...) | - |
| `ginadapter` | `net/http` middleware and routes on gin, `Require` and `RequireMethodPermission`, wide-event `Observe` | gin, go-wide-event-logger |
| `prometheusadapter` | `Observer` that counts outcomes on your registry | client_golang |
| `cmd/forwardauth` | the forward-auth binary, image `ghcr.io/govengers/forwardauth` | - |

The examples below share two helpers:

```go
// must keeps startup code short; it is only used in main.
func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
}

// newStore builds the session store every example shares. Generate the key with
// `openssl rand -base64 32` and give every replica the same one.
func newStore(backend session.Backend) *session.Store {
	key := must(session.ParseKey(os.Getenv("SESSION_ENCRYPTION_KEY")))
	return must(session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key}))
}
```

Fragments below use `store` (from `newStore`), `guard` (a `*session.Guard`), `mux` (an `*http.ServeMux`), `engine` (a `*gin.Engine`) and `ctx`; handlers such as `index` or `orders` are yours.

Constructors take an options pointer, validate it, copy what they keep and never write to your struct. Components never log and never start goroutines; they report outcomes to an optional `auth.Observer`. Errors are `*auth.Error` and answer with one shape, `{"code","message"}`; branch with `errors.Is(err, auth.ErrUnauthenticated | auth.ErrForbidden | auth.ErrInvalidRequest | auth.ErrConflict)`.

## Password login

Users live in your database behind `password.Storage`; `password.NewMemoryStorage()` is for tests and examples.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/govengers/auth"
	"github.com/govengers/auth/password"
	"github.com/govengers/auth/session"
)

func main() {
	storage := password.NewMemoryStorage() // seeded with one user; yours reads your database
	hash := must(password.Hash("correct horse battery", password.DefaultParameters()))
	if err := storage.CreateUser(context.Background(), &password.User{ID: uuid.New(), Username: new("alice"), PasswordHash: hash}); err != nil {
		log.Fatal(err)
	}

	store := newStore(must(session.NewMemoryBackend(nil))) // one replica; Redis below
	provider := must(password.New(&password.Options{
		Sessions: store,
		Storage:  storage,
		TOTP:     password.TOTPOptions{Enabled: true, Issuer: "Example"},
	}))
	guard := must(session.NewGuard(&session.GuardOptions{
		Store:      store,
		Refreshers: []session.Refresher{provider}, // a deleted user loses access within a minute
	}))

	mux := http.NewServeMux()
	auth.RegisterRoutes(mux, provider.Routes())
	mux.Handle("GET /auth/me", guard.RequireAPI()(auth.IdentityHandler()))
	mux.Handle("GET /api/hello", guard.RequireAPI()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s\n", auth.IdentityFrom(r.Context()).Username)
	})))
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

```bash
curl -c jar -H 'Content-Type: application/json' -d '{"identifier":"alice","password":"correct horse battery"}' localhost:8080/auth/password/login
curl -b jar localhost:8080/api/hello
```

The provider reads sessions itself, so its routes need no Guard. All bodies are JSON (`Content-Type: application/json`, at most 64 KiB, unknown fields refused).

| Route | Answer |
|---|---|
| `POST /auth/password/login` `{"identifier","password"}` | 200 identity, or 202 `{"challenge":"totp"}` / `{"challenge":"totp_setup"}` |
| `POST /auth/password/logout` | 204; 403 `forbidden` for a request the browser marks `Sec-Fetch-Site: cross-site` |
| `POST /auth/password/register` (only with `EnableRegistration`) | 201 identity, or 202 `{"challenge":"totp_setup"}` with `TOTP.Required` |
| `POST /auth/password/totp/verify` `{"code","backupCode":false}` (this and the routes below only with `TOTP.Enabled`) | 200 identity; `"backupCode":true` checks the code against the backup codes only, `false` against the TOTP codes only |
| `GET /auth/password/totp` | 200 `{"enabled"}` |
| `POST /auth/password/totp/setup` `{}` | 200 `{"secret","otpauthUrl","issuer","accountName"}` |
| `POST /auth/password/totp/enable` `{"code","password"}` | 200 `{"backupCodes":[...]}`; a wrong code can be retried with the same setup; 409 `totp_already_enabled` when a concurrent enrollment won |
| `POST /auth/password/totp/disable` `{"password"}` | 204; a pending setup is dropped, so enable needs a new one |

- `TOTP.Required` enrolls users without a second factor during login and registration (the 202 `totp_setup` challenge, then `/totp/setup` and `/totp/enable`) instead of failing every route. `TOTP.Digits` is 6 or 8, `Period` at most 3600 s, `Skew` at most 10, `BackupCodeCount` at most 20; backup codes are at most 128 bytes and the alphabet and length must give at least 1,000,000 distinct codes.
- Every TOTP code is accepted once (`Storage.ConsumeTOTPStep`). `MaximumAttempts` (default 5, no "unlimited") counts wrong codes in a row across logins; then the second factor stays locked until a code is verified or your application calls `Storage.ResetTOTPAttempts`. Whoever knows the password can therefore lock the second factor; put a rate limit on `/auth/password/login` and `/auth/password/totp/verify` at the edge.
- With `TOTP.Enabled` off, users who enrolled cannot log in (500): clear their TOTP in storage before switching it off.
- `Policy.MinimumLength` (default 12) counts characters; passwords are at most 128 bytes. Stable client codes (see [Errors](#errors)) replace translated messages.
- Existing Argon2id hashes verify unchanged; `LegacyVerifier: password.VerifyBcrypt` upgrades bcrypt hashes at the next login, and Argon2id hashes on other parameters than `HashParameters` are rehashed too (only login rehashes, not the password checks of the TOTP routes). A stored hash nothing can verify answers like a wrong password (401 `invalid_credentials`, same cost).
- Your `Storage` matches usernames and emails ignoring case (unique indexes on `lower(...)`), and `SetTOTP` enables TOTP only while it is off, in one atomic step, reporting whether it did; [docs/migration.md](docs/migration.md) has the SQL for every method.
- `PathPrefix` (default `/auth/password`) is made of `/`-separated segments of `A-Z a-z 0-9 . _ ~ -`, without a trailing `/`; the same rule applies to the OIDC and GitHub providers.

## OIDC with Keycloak

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/govengers/auth"
	"github.com/govengers/auth/oidc"
	"github.com/govengers/auth/oidc/keycloak"
	"github.com/govengers/auth/session"
)

func main() {
	ctx := context.Background()
	store := newStore(must(session.NewMemoryBackend(nil)))

	enricher := must(keycloak.New(&keycloak.Options{
		URL:                 "https://keycloak.example.com",
		Realm:               "example",
		ClientID:            "app-admin", // service account, see below
		ClientSecret:        os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		ClientRolesClientID: "app",
		RequiredRealmRoles:  []string{"app-user"},
	}))
	provider := must(oidc.New(ctx, &oidc.Options{ // runs discovery, fails fast
		Name:         "keycloak",
		Issuer:       "https://keycloak.example.com/realms/example",
		ClientID:     "app",
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		ExternalURL:  "https://app.example.com",
		ErrorURL:     "/login-failed", // optional: callback failures redirect here with ?code=<code>
		Sessions:     store,
		OnLogin:      enricher.Enrich,
	}))
	guard := must(session.NewGuard(&session.GuardOptions{Store: store, LoginURL: provider.LoginURL()}))

	mux := http.NewServeMux()
	auth.RegisterRoutes(mux, provider.Routes()) // GET /auth/oidc/keycloak/{login,callback,logout,frontchannel-logout}
	mux.Handle("GET /dashboard", guard.RequireUI()(http.HandlerFunc(dashboard)))
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

- Register `https://app.example.com/auth/oidc/keycloak/callback` at the IdP. The redirect URI is derived from `ExternalURL` and `PathPrefix`, the end-session endpoint is discovered. The issuer and the endpoints its discovery names (authorization, token, JWKS, end session) must be `https` (`http` only on loopback hosts, for tests), else `oidc.New` fails.
- `RequireUI` answers 302 to `<login>?return_to=<path>`; the user returns to the original path after login. Use `RequireAPI` for JSON endpoints.
- `Enrich` replaces roles, client roles, groups (paths) and attributes with the Admin API's answer and refuses the login (403, role name stays server-side) when a required role or group is missing. Give the service account the `realm-management` roles `view-users`, `query-users`, `view-clients`, `query-clients`, `query-groups`. The default grant is `client_credentials`; the `password` grant (client `admin-cli` by default) breaks as soon as the admin user gets an OTP credential. `RequiredClientRoles` needs `ClientRolesClientID`.
- Without Keycloak, realm roles (`realm_access.roles`), client roles (`resource_access.<client>.roles`) and groups (`groups`) are read from the access token first and, per claim, from the ID token when the access token lacks it.
- Google: `Issuer: "https://accounts.google.com"`, `ClaimMapper: oidc.GoogleClaimMapper`, and set `AllowedEmailDomains` (requires `email_verified`), otherwise any Google account gets in.
- One `oidc.New` per identity provider, one shared `Store`, distinct `Name`s (`[a-z0-9-]{1,32}`; `password`, `github`, `apikey`, `session` and `jwt` are taken).
- `PostLogoutURL` (default `ExternalURL/`) and `ErrorURL` take a path or an absolute `http(s)` URL without fragment; a path is made absolute with `ExternalURL`. With `ErrorURL`, every callback failure redirects to `ErrorURL?code=<code>` (`code=internal` for a server-side failure) instead of answering JSON.
- The IdP rejecting the authorization code (an error answer below 500) is 401 `login_failed`; a 5xx answer or an IdP that cannot be reached is 500. An ID token without `sub` is refused; one that does not verify is 401 `login_failed` with the fixed Reason `ID token expired` or `ID token verification` on the outcome (an unreachable JWKS reads like an invalid token: go-oidc's message quotes the token and the server's text).
- `GET .../logout` ends the local session and sends the browser to the IdP's end-session endpoint with the stored ID token as hint. Without a stored ID token (the local session had already expired) it goes straight to `PostLogoutURL` and the IdP session stays. A logout link on another site (`Sec-Fetch-Site: cross-site`) gets 403 `forbidden` and ends nothing; front-channel logout from the IdP's iframe still works.
- Front-channel logout needs `StoreOptions.SameSite: http.SameSiteNoneMode` (HTTPS only).

## GitHub login with teams

```go
provider := must(github.New(&github.Options{
	ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
	ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	ExternalURL:  "https://app.example.com",
	AllowedTeams: []string{"acme/engineering"}, // required, "org/team-slug", case-insensitive
	AdminTeams:   []string{"acme/platform"},    // members get auth.RoleAdmin, if they are in an allowed team too
	Sessions:     store,
}))
guard := must(session.NewGuard(&session.GuardOptions{
	Store:      store,
	LoginURL:   provider.LoginURL(),
	Refreshers: []session.Refresher{provider}, // refetches teams every minute
}))

mux := http.NewServeMux()
auth.RegisterRoutes(mux, provider.Routes()) // GET /auth/github/{login,callback,logout}, POST /auth/github/refresh-teams
mux.Handle("GET /", guard.RequireUI()(http.HandlerFunc(index)))
```

Imports are `github.com/govengers/auth/github` (package `github`) and the packages above. Register `https://app.example.com/auth/github/callback` as the OAuth app's callback URL.

- Users outside `AllowedTeams` get 403 and no session; an `AdminTeams` membership alone is not enough. A user removed from every allowed team loses the session at the next refresh. When the refresh fails otherwise (GitHub outage, rate limit), the session keeps its teams and roles, at most for the Guard's `MaximumUnverifiedAge` (default 1 h) since the last successful check; after that the session ends (or `POST /auth/github/refresh-teams`; when that route cannot end the session it answers 500 instead of 401/403). refresh-teams never overwrites a change another request saved while it called GitHub: it applies the teams to that save once more, and answers 409 `conflict` when that save changed the membership, the admin role or the user (it may be a newer refresh) or the session changed again. Like logout it refuses a cross-site request (`Sec-Fetch-Site: cross-site`) with 403 before GitHub is called.
- `Identity.Teams` holds only teams in the allowed, admin and relevant lists (`RelevantTeams`), lower-case, sorted. `Subject` is the numeric GitHub user ID, `Username` the login.
- The GitHub token never leaves the server: call the GitHub API as the user with `provider.HTTPClient(ctx, current)` (`current` from `store.Open(request)`). That client sends the token only to the `APIURL` host; a redirect to another host (archive downloads, `uploads.github.com`) goes without it.
- `Scopes` (default `read:org`) must include one that lists the user's teams: `read:org`, `write:org`, `admin:org`, `user` or `repo`; `github.New` refuses others.
- `PostLogoutURL` and `ErrorURL` work as for OIDC. GitHub refusing the code is 401 `login_failed`; a GitHub outage is 500. Logout revokes the token at GitHub (a failure only shows in the outcome); like OIDC logout it refuses a cross-site request with 403.
- GitHub Enterprise: set `AuthorizeURL`, `TokenURL` and `APIURL` (`https`, `http` only on loopback hosts; `APIURL` without query or fragment).

Run it as a forward-auth proxy instead of a library with `PROVIDER=github` ([image](#forward-auth-image)).

## Backend JWT verification

The forward-auth image (and any `jwt.Signer`) mints a short-lived RS512 token per request. A backend verifies it against the JWKS endpoint and gets an `auth.Identity` without sessions:

```go
verifier := must(jwt.NewVerifier(ctx, &jwt.VerifierOptions{ // fetches the JWKS once, fails fast
	JWKSURL:  "http://forwardauth:8080/auth/jwks", // may be the internal address
	Issuer:   "https://app.example.com",           // JWT_ISSUER of the proxy, default EXTERNAL_URL
	Audience: "orders-api",                        // optional
}))

mux.Handle("GET /orders", verifier.Middleware()(http.HandlerFunc(orders))) // 401 JSON when missing or invalid

// or in gin
ordersGroup := engine.Group("/orders", ginadapter.Middleware(verifier.Middleware()), ginadapter.Require(authorization.HasOIDCRole("orders")))
ordersGroup.GET("", listOrders)
```

- `Verify(ctx, token)` checks the signature (with the JWKS key the token's `kid` names, under that key's algorithm), `iss`, `aud`, `exp` (required), `nbf` and `iat` (30 s skew) and returns the identity: `sub` is `Subject`, `preferred_username` is `Username`, `provider`, `user_id`, `name`, `email`, `picture`, `roles`, `realm_roles`, `client_roles`, `groups`, `teams` fill the matching fields, `permissions` fills `Permissions` (entries that do not parse are dropped), and `Claims` holds all claims.
- The middleware reads `Authorization: Bearer <token>` (scheme in any case, spaces around the token ignored) and answers a missing token with 401 `unauthenticated`, an invalid one with 401 `invalid_token`, both with `WWW-Authenticate: Bearer`. Why a token was refused (expired, issuer mismatch, ...) is in the outcome's Reason, never token content.
- Only RSA keys with an RSA signature `alg` (RS256/384/512, PS256/384/512), a `kid` and use `sig` (or none) count from the JWKS; other keys and entries that do not parse are ignored, and a JWKS without a usable key, that is not a JSON JWK set or larger than 1 MiB fails `NewVerifier`. Errors name the JWKS URL without credentials and query and never repeat the answer's bytes.
- The JWKS is refetched after `RefreshInterval` (default 1 h, at least 1 min) or for an unknown key ID, at most once a minute, detached from the request that triggered it and bounded by 10 s. While it runs, tokens with a known key ID verify with the current keys; tokens with an unknown one wait for it, at most until their own request ends. A failed refetch keeps the previous keys; a token signed with an unknown key then gets 500. There is no token cache and no goroutine.
- `Signer.Sign` refuses an inactive identity (403 `forbidden`): a verified token always yields an active identity.
- Do not put `apikey` middleware in front of the verifier: both read `Authorization: Bearer`.

## Authorization

A `Check` allows with `nil` and refuses with an `*auth.Error` (401 without identity, 403 otherwise). `IsAuthenticated` passes any identity; the other primitives require an active one: `IsActive`, `IsUser`, `IsAdmin`, `HasRole`, `HasUserID`, `HasOIDCRole`, `HasOIDCGroup`, `HasGitHubTeam`, `HasPermission`. Combinators: `All` (first refusal), `Any`, `Not`, `Real` (evaluates against the real identity while someone impersonates another). `Not` refuses a missing or inactive identity before it inverts, so `Not(HasRole("x"))` never admits anonymous or deactivated users, and it inverts only a refusal answered 403 (the kind of the outermost `*auth.Error`, as `auth.ResponseFor` decides), never a 401 that wraps a forbidden cause. A wiring mistake (a `nil` check, `All()` or `Any()` without checks, `HasPermission` with an invalid resource or access) answers every request with 500, and `Not` passes that through instead of inverting it. `Any` returns a failed check (500) in preference to a refusal for the same reason.

```go
var editors = authorization.Any(
	authorization.IsAdmin(),
	authorization.All(
		authorization.HasOIDCRole("editor"),
		authorization.Not(authorization.HasOIDCGroup("/contractors")),
	),
)

// gin: 401/403/500 JSON, recorded on the wide event.
func articleRoutes(engine *gin.Engine, guard *session.Guard) {
	api := engine.Group("/api", ginadapter.Middleware(guard.RequireAPI()))
	api.PUT("/articles/:id", ginadapter.Require(editors), updateArticle)
}

// net/http: call the check in the handler.
func updateHandler(w http.ResponseWriter, r *http.Request) {
	if err := editors(r.Context()); err != nil {
		auth.WriteError(w, err) // generic body; the Reason stays server-side
		return
	}
	// ...
}

// Your own checks have the same shape.
func HasTenant(tenant string) authorization.Check {
	return func(ctx context.Context) error {
		if err := authorization.IsActive()(ctx); err != nil {
			return err
		}
		if auth.IdentityFrom(ctx).Data["tenant"] != tenant {
			return &auth.Error{Kind: auth.ErrForbidden, Reason: "tenant " + tenant + " required"}
		}
		return nil
	}
}
```

Entity checks (`CanViewOrder`), tenant roles and broadcast filters belong in your application; they are plain `Check`s that read `auth.IdentityFrom(ctx)`.

## Permissions

An `auth.Permission` grants `read` or `write` on one resource; `write` includes `read`, and the resource `*` (`auth.AllResources`) covers every resource. Its text form `<resource>:<access>` (`builds:write`, `*:read`) is the same in Go (`ParsePermission`, `String`), JSON, the JWT `permissions` claim and the image's `API_KEY_PERMISSIONS`. A resource is `*` or matches `[a-z0-9][a-z0-9._-]{0,63}`; parsing is case-sensitive, so a typo fails at startup. No permission means no access.

```go
ci := must(apikey.New(&apikey.Options{
	Keys: []apikey.Key{{
		Name:        "ci",
		Secret:      os.Getenv("CI_API_KEY"),
		Permissions: []auth.Permission{must(auth.ParsePermission("builds:write"))},
	}},
}))

builds := engine.Group("/api/builds",
	ginadapter.Middleware(ci.Middleware()),
	ginadapter.Middleware(guard.RequireAPI()),
	ginadapter.RequireMethodPermission("builds"), // GET, HEAD, OPTIONS need builds:read, every other method builds:write
)
builds.GET("", listBuilds)
builds.POST("", createBuild)

// one route, one explicit permission
engine.GET("/api/reports", ginadapter.Middleware(guard.RequireAPI()), ginadapter.Require(authorization.HasPermission("reports", auth.AccessRead)), reports)
```

Identities get permissions from API keys (`Key.Permissions`, or the identity your `Resolver` returns), from verified JWTs (the `permissions` claim) and from `OnLogin` hooks. Browser sessions carry none unless a hook grants them, so grant them at login or accept a role as an alternative:

```go
onLogin := func(ctx context.Context, identity *auth.Identity) (*auth.Identity, error) {
	granted := identity.Clone() // hooks must not mutate their argument
	granted.Permissions = append(granted.Permissions, auth.Permission{Resource: auth.AllResources, Access: auth.AccessWrite})
	return granted, nil
}
writers := authorization.Any(authorization.HasRole("editor"), authorization.HasPermission("builds", auth.AccessWrite))
```

`HasPermission` checks the effective identity (wrap it in `Real` for the impersonator). In your own code, `identity.Permits(resource, access)` applies the same rule, and `auth.AccessForMethod(method)` maps an HTTP method to the access it needs.

## Errors

Every response the library writes is `{"code","message"}` with `Cache-Control: no-store`. The message is fixed per kind; the code is stable and meant for frontends.

| Kind (`errors.Is`) | Status | Default code |
|---|---|---|
| `auth.ErrUnauthenticated` | 401 | `unauthenticated` |
| `auth.ErrForbidden` | 403 | `forbidden` |
| `auth.ErrInvalidRequest` | 400 | `invalid_request` |
| `auth.ErrConflict` | 409 | `conflict` |
| anything else | 500 | `internal` |

| Code | Kind | Raised by |
|---|---|---|
| `invalid_credentials` | unauthenticated | password login, TOTP enable and disable |
| `no_pending_login`, `invalid_totp_code` | unauthenticated | password TOTP verify (`invalid_totp_code` also on enable) |
| `totp_setup_missing` | invalid request | password TOTP enable |
| `totp_already_enabled`, `totp_not_enabled` | conflict | password TOTP setup, enable, disable |
| `user_exists` | conflict | password register |
| `weak_password`, `invalid_username`, `invalid_email` | invalid request | password register |
| `login_expired`, `state_mismatch` | invalid request | OIDC and GitHub callback |
| `login_denied`, `login_failed` | unauthenticated | OIDC and GitHub callback |
| `invalid_api_key` | unauthenticated | `apikey` |
| `invalid_token` | unauthenticated | `jwt` verifier |

With `ErrorURL` set, OIDC and GitHub callbacks send the same codes as `?code=<code>`, `internal` included. Your own code returns `&auth.Error{Kind: auth.ErrForbidden, Code: "plan_limit", Reason: "..."}`: `Code` replaces the default code, `Reason` and the wrapped cause never reach the client.

## gin

`ginadapter` runs any `net/http` middleware in a gin chain and registers provider routes on gin, so route templates (and metric labels) are the provider paths.

```go
registry := prometheus.NewRegistry()
counter := must(prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: "app"}))
observe := func(ctx context.Context, outcome auth.Outcome) {
	ginadapter.Observe(ctx, outcome) // fields on the request's wide event; a no-op without one
	counter.Observe(ctx, outcome)    // app_auth_outcomes_total{provider,action,result}
}

provider := must(password.New(&password.Options{Sessions: store, Storage: storage, Observer: observe}))
guard := must(session.NewGuard(&session.GuardOptions{Store: store, Refreshers: []session.Refresher{provider}, Observer: observe}))

engine := gin.New() // mount the go-wide-event-logger middleware first
ginadapter.RegisterRoutes(engine, provider.Routes()) // on the engine root: route paths are absolute
api := engine.Group("/api", ginadapter.Middleware(guard.RequireAPI()))
api.GET("/profile", func(c *gin.Context) {
	c.JSON(http.StatusOK, auth.NewIdentityResponse(auth.IdentityFrom(c.Request.Context())))
})
api.DELETE("/users/:id", ginadapter.Require(authorization.IsAdmin()), deleteUser)
```

After `ginadapter.Middleware(...)` calls its next handler, `c.Request` is the enriched request, so later gin handlers and middleware see the identity. If the wrapped middleware refuses, the chain is aborted. It wraps the middleware once, like a `net/http` chain, so state the middleware keeps across requests survives; pass the request on with a context derived from the one it got (`r.WithContext(context.WithValue(r.Context(), ...))`), else the request is answered 500. `ginadapter.Require(nil)` answers every request with 500 (a wiring mistake fails closed). `IdentityResponse` never exposes `Claims`, `Attributes` or `Data`.

## Your application user (replaces `UserTransformer`)

`go-basicauth` let a `UserTransformer` swap the stored user for your own type. Now the Guard puts an `auth.Identity` in the context and your own middleware loads your user after it. `UserRepository`, `User` and `Provision` are yours:

```go
type userKey struct{}

// WithUser loads the application user of the authenticated identity and refuses inactive users.
func WithUser(users UserRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := auth.IdentityFrom(r.Context())
			if identity == nil {
				auth.WriteError(w, &auth.Error{Kind: auth.ErrUnauthenticated})
				return
			}
			user, err := users.ByID(r.Context(), identity.UserID)
			if err != nil {
				auth.WriteError(w, err) // plain errors answer 500
				return
			}
			if !user.Active {
				auth.WriteError(w, &auth.Error{Kind: auth.ErrForbidden, Reason: "inactive user"})
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
		})
	}
}

// UserFrom returns the user WithUser stored, or nil.
func UserFrom(ctx context.Context) *User {
	user, _ := ctx.Value(userKey{}).(*User)
	return user
}
```

In `main`, run the Guard first, then `WithUser`: `guard.RequireAPI()(WithUser(users)(handler))`. In gin, use `ginadapter.Middleware(WithUser(users))` after `ginadapter.Middleware(guard.RequireAPI())`. A hook cannot add your user object to the context, which is why this is a middleware.

The password provider sets `UserID` itself (the `Storage` user ID); its `OnLogin` hook must keep it, a hook that replaces it fails the login with 500. For OIDC and GitHub, provision the user at login in `OnLogin` so the identity carries your user ID:

```go
onLogin := func(ctx context.Context, identity *auth.Identity) (*auth.Identity, error) {
	enriched, err := enricher.Enrich(ctx, identity) // returns a copy; hooks must not mutate their argument
	if err != nil {
		return nil, err
	}
	user, err := users.Provision(ctx, enriched.Provider, enriched.Subject, enriched.Email)
	if err != nil {
		return nil, err
	}
	enriched.UserID = user.ID
	return enriched, nil
}
// oidc.Options{..., OnLogin: onLogin}
```

An `*auth.Error` from a hook answers with its status (403 refuses the login), anything else with 500; no session is created either way. `OnLogout` gets a context a disconnecting client cannot cancel (every provider); set your own deadline for slow work in it.

## API keys

```go
keys := must(apikey.New(&apikey.Options{
	Keys: []apikey.Key{{
		Name:        "ci",
		Secret:      os.Getenv("CI_API_KEY"), // at least 16 bytes
		Permissions: []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}},
	}},
	Resolver: lookupKey, // yours: keys you issue per user, see below
}))
mux.Handle("GET /api/hello", keys.Middleware()(guard.RequireAPI()(hello)))
```

- Keys come from `X-API-Key` (`HeaderName`; it cannot be `Authorization`) or `Authorization: Bearer <key>` (scheme in any case). No key passes through to the Guard; a wrong key is 401 `invalid_api_key` and never falls through, also when the request carries a valid session cookie. So any other bearer token (an SPA's own) on a route behind `apikey` is refused.
- A static key's identity has `Provider` `apikey`, `Subject` and `Username` = the key name, and the key's `Roles` and `Permissions`. Names and secrets must be unique; secrets have at least 16 bytes and no surrounding whitespace. Static keys are compared as SHA-256 hashes in constant time.
- `Resolver` (`func(ctx, key) (*auth.Identity, error)`) looks up keys you issue (per user, revocable). Return an error matching `auth.ErrUnauthenticated` for unknown or revoked keys; any other error answers 500 (its chain is dropped, only `context.Canceled` and `context.DeadlineExceeded` stay detectable). The returned identity carries its own `Permissions` (e.g. a stored `read_only` level becomes `*:read`). Set `Active`: the Authenticator does not, and every check but `IsAuthenticated` refuses an inactive identity (403, Reason `inactive`). The error's text is reported in `Outcome.Err` and recorded on the wide event, so it must not repeat the key.

## Several replicas

The memory backend is correct for exactly one replica, forgets sessions on restart and is meant for non-production scale: when full (`MaximumSessions`, default 100000, or `MaximumBytes` of session IDs, keys and values, default 64 MiB) it drops expired entries, then evicts the entries expiring soonest, revocation markers included; a single value larger than `MaximumBytes` is refused. In production, and for more than one replica, share one Redis and one `EncryptionKey`:

```go
client := redis.NewClient(&redis.Options{Addr: "redis:6379"}) // github.com/redis/go-redis/v9; you own and close it
defer client.Close()

backend := must(redisbackend.New(&redisbackend.Options{Client: client, KeyPrefix: "myapp"}))
store := newStore(backend)
```

`redisbackend` takes any `redis.UniversalClient` (client, sentinel, cluster; keys carry a hash tag, so `KeyPrefix` must not contain `{` or `}`). Logout and session rotation revoke on every replica; a revoked session never regains an identity and refuses writes while its revocation marker lives (Redis may evict it under its own eviction policy, as a full memory backend does). To use another database, implement the five-method `session.Backend` (`Put`, `Get`, `Pop`, `CompareAndSwap`, `Revoke`). A Redis dump holds SHA-256 hashes of session IDs and AES-256-GCM ciphertext, not usable cookies.

## Forward-auth image

`ghcr.io/govengers/forwardauth` (about 22 MB, distroless `static-debian13`, non-root, `linux/amd64` and `linux/arm64`, ports 8080 and 9090) runs one provider, `PROVIDER=oidc` or `PROVIDER=github`, in front of any app behind Traefik. Tags: `:1.0.0`, `:1.0`, `:1` and `:latest` per release, `:main` from the main branch. Traefik calls `GET /auth/ui` (browsers) or `GET /auth/api` (APIs) for each request. 200 lets the request through, with a signed JWT in `Authorization` when `JWT_ENABLED`; anything else (302 to the login, 401, 403) goes to the client. Password login is not offered (Traefik's `basicAuth` covers static users). One instance serves one external origin. Without Redis it is a single replica.

### Quick start (docker compose)

A local stack on plain HTTP at `http://app.localhost` (browsers resolve `*.localhost` to the loopback address); production with TLS below.

```yaml
services:
  traefik:
    image: traefik:v3.7
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.web.http.aliasHeadersStrategy=delete
    ports: ["80:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]

  forwardauth:
    image: ghcr.io/govengers/forwardauth:1.0.0
    environment:
      PROVIDER: oidc
      EXTERNAL_URL: http://app.localhost
      SESSION_INSECURE_COOKIE: "true"                     # the cookie travels over plain HTTP; local only
      SESSION_ENCRYPTION_KEY: ${SESSION_ENCRYPTION_KEY}   # openssl rand -base64 32
      OIDC_ISSUER: https://keycloak.example.com/realms/example
      OIDC_CLIENT_ID: app
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      JWT_ENABLED: "true"
      JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY}                 # export JWT_PRIVATE_KEY="$(cat jwt.pem)"
    labels:
      - traefik.enable=true
      # login, callback, logout, jwks; never the checks or the probes. No forwardAuth middleware; its longer rule wins
      - traefik.http.routers.app-auth.rule=Host(`app.localhost`) && PathPrefix(`/auth`) && !Path(`/auth/ui`) && !Path(`/auth/api`) && !Path(`/auth/health`) && !Path(`/auth/ready`)
      - traefik.http.routers.app-auth.service=forwardauth
      - traefik.http.services.forwardauth.loadbalancer.server.port=8080
      # UI variant: unauthenticated browsers are redirected to the login
      - traefik.http.middlewares.forwardauth-ui.forwardauth.address=http://forwardauth:8080/auth/ui
      - traefik.http.middlewares.forwardauth-ui.forwardauth.authResponseHeaders=Authorization,X-API-Key
      - traefik.http.middlewares.forwardauth-ui.forwardauth.trustForwardHeader=false
      - traefik.http.middlewares.forwardauth-ui.forwardauth.maxResponseBodySize=65536
      # API variant: unauthenticated clients get 401 JSON
      - traefik.http.middlewares.forwardauth-api.forwardauth.address=http://forwardauth:8080/auth/api
      - traefik.http.middlewares.forwardauth-api.forwardauth.authResponseHeaders=Authorization,X-API-Key
      - traefik.http.middlewares.forwardauth-api.forwardauth.trustForwardHeader=false
      - traefik.http.middlewares.forwardauth-api.forwardauth.maxResponseBodySize=65536

  app:
    image: traefik/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.app.rule=Host(`app.localhost`)
      - traefik.http.routers.app.middlewares=forwardauth-ui
      - traefik.http.routers.app-api.rule=Host(`app.localhost`) && PathPrefix(`/api`)
      - traefik.http.routers.app-api.middlewares=forwardauth-api
```

Generate the JWT key with `openssl genrsa -out jwt.pem 3072` (PKCS#1 or PKCS#8 PEM, at least 2048 bits). Register `http://app.localhost/auth/oidc/oidc/callback` (`<EXTERNAL_URL><PATH_PREFIX>/oidc/<OIDC_NAME>/callback`) at the IdP, or `http://app.localhost/auth/github/callback` for GitHub, then open `http://app.localhost`.

The `/auth` router keeps the checks and the probes off the public route: through it a same-origin script could read the bearer JWT of a check answer, and every anonymous `/auth/ready` would cost a Redis `PING`. Traefik calls the checks on the internal address, Kubernetes probes reach the pod directly. Traefik v3 matchers take one value each, hence one `!Path` per route.

Production: `EXTERNAL_URL: https://app.example.com` without `SESSION_INSECURE_COOKIE`, the routers on ``Host(`app.example.com`)``, and a TLS entrypoint in Traefik: `--entrypoints.websecure.address=:443`, `--entrypoints.websecure.http.tls.certresolver=<your resolver>`, `--entrypoints.websecure.http.aliasHeadersStrategy=delete` and `--entrypoints.web.http.redirections.entrypoint.to=websecure`, with port 443 published. Register the `https://` callback URL.

Traefik settings that matter (verified on Traefik v3.7):

- `authResponseHeaders: [Authorization, X-API-Key]`: Traefik deletes the client's `Authorization` and `X-API-Key` headers and puts the JWT in place of the first; with JWT disabled both are simply gone. A forged token never reaches the app, and neither does a raw API key: both headers reach forwardauth only, where they are the API key credential. A different `JWT_HEADER` goes into the list as well.
- `trustForwardHeader: false`: client-sent `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Forwarded-Uri` never reach forwardauth, so they cannot steer the return path. Set it `true` only behind another trusted proxy.
- `aliasHeadersStrategy: delete` on the entrypoints: headers like `X_Auth_User` cannot alias a header the auth response sets.
- `maxResponseBodySize` bounds what Traefik reads from forwardauth.
- forwardauth answers redirects with absolute URLs; Traefik resolves a relative `Location` against the forwardAuth address (`http://forwardauth:8080/...`).

Kubernetes, with the Traefik CRDs (set `aliasHeadersStrategy: delete` on the entrypoints in Traefik's static configuration):

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: forwardauth-ui
  namespace: default
spec:
  forwardAuth:
    address: http://forwardauth.default.svc.cluster.local:8080/auth/ui
    authResponseHeaders:
      - Authorization
      - X-API-Key
    trustForwardHeader: false
    maxResponseBodySize: 65536
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: app
  namespace: default
spec:
  routes:
    # no middleware here; the checks and probes stay internal
    - match: Host(`app.example.com`) && PathPrefix(`/auth`) && !Path(`/auth/ui`) && !Path(`/auth/api`) && !Path(`/auth/health`) && !Path(`/auth/ready`)
      kind: Rule
      services:
        - name: forwardauth
          port: 8080
    - match: Host(`app.example.com`)
      kind: Rule
      middlewares:
        - name: forwardauth-ui
      services:
        - name: app
          port: 80
```

Set `GOMEMLIMIT` 5-10 % below the container memory limit in your manifests (limit 256Mi, `GOMEMLIMIT=230MiB`); Go reads the CPU limit itself. The default termination grace period of 30 s covers the shutdown (readiness 503 for `SHUTDOWN_DELAY_SECONDS`, at most 10, then a 20 s drain). Point the liveness and readiness probes at `{prefix}/health` and `{prefix}/ready` on port 8080 of the pod.

### Routes

`{prefix}` is `PATH_PREFIX` (default `/auth`).

| Route | Purpose |
|---|---|
| `GET {prefix}/ui` | forward-auth check for browsers: 302 to the login when unauthenticated |
| `GET {prefix}/api` | forward-auth check for APIs: 401 JSON when unauthenticated |
| `GET {prefix}/jwks` | public keys of the JWT signer (`JWT_ENABLED`), `Cache-Control: public, max-age=300` |
| `GET {prefix}/me` | the caller's identity as JSON (`IDENTITY_ENDPOINT_ENABLED`; sessions only, not API keys) |
| `GET {prefix}/health` | liveness, 200 `{"status":"ok"}` |
| `GET {prefix}/ready` | readiness: 200 `{"status":"ok"}`, or 503 `{"code":"unavailable","message":"not ready"}` during shutdown or when the Redis ping (2 s) fails; a failed ping is kept as a wide event, successful probes are sampled |
| `GET {prefix}/oidc/<OIDC_NAME>/{login,callback,logout,frontchannel-logout}` | OIDC provider |
| `GET {prefix}/github/{login,callback,logout}`, `POST {prefix}/github/refresh-teams` | GitHub provider |
| any other path | 404 `{"code":"not_found","message":"not found"}`, also a known route with a trailing `/` (no redirect) |
| `GET /metrics` on `METRICS_PORT` | Prometheus, the only route of that listener; keep this port off Traefik |

Route `{prefix}` to the service with its own Traefik router, minus the checks and probes, as in the labels above: the check endpoints do not dispatch login routes by `X-Forwarded-Uri`. Link users to `{prefix}/oidc/<name>/logout` or `{prefix}/github/logout` to log out; both are plain `GET` links, same-site only: a link from another site (`Sec-Fetch-Site: cross-site`, e.g. a portal on another domain) is refused with 403.

### Environment variables

Values without a default are required. *not empty* marks values with a default that refuse an explicitly empty value. Lists are comma-separated. The process exits non-zero before it serves anything and lists every problem it can find: missing or invalid values, an `EXTERNAL_URL` with a path, a plain `http` `EXTERNAL_URL` off loopback without `SESSION_INSECURE_COOKIE=true` (browsers would drop the `Secure` cookie and loop every login), an unparsable `SESSION_ENCRYPTION_KEY`, `PORT` equal to `METRICS_PORT`, values the selected provider, Keycloak or JWT needs, `KEYCLOAK_ENABLED` without `PROVIDER=oidc`, `API_KEYS_ENABLED` without keys, a malformed `API_KEYS` entry (reported by position, never echoed), a secret that is too short or used twice, a bad `API_KEY_PERMISSIONS` entry. Then the components fail the boot on what only they can judge (team format, `GITHUB_SCOPES`, URLs, the JWT key, the issuer's discovery) and, with `SESSION_REDIS_ENABLED`, on a Redis that does not answer a `PING` within 5 s. Sensitive values are masked in the startup table. A `.env` file in the working directory is read if present (development only; the image has none).

**General**

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `PROVIDER` | - | yes | | `oidc` or `github` |
| `EXTERNAL_URL` | - | yes | | public origin of the protected app, scheme and host without a path, e.g. `https://app.example.com` |
| `PATH_PREFIX` | `/auth` | not empty | | prefix of every route; starts with `/`, no trailing `/`, segments of `A-Z a-z 0-9 . _ ~ -`, no `.` or `..` segment |
| `PORT` | `8080` | | | public listener, 1-65535 |
| `METRICS_PORT` | `9090` | | | `/metrics` listener, 1-65535; must differ from `PORT` |
| `DEV_MODE` | `false` | | | development wide-event emitter, gin debug mode |
| `WIDE_EVENT_SAMPLE_RATE` | `10` | | | at least 1; keep every Nth successful event; failures, 401, 403 and degraded events are always kept |
| `SHUTDOWN_DELAY_SECONDS` | `5` | | | readiness 503 this long before draining; 0-10, so delay plus the 20 s drain fit the 30 s default grace period |
| `IDENTITY_ENDPOINT_ENABLED` | `false` | | | mounts `{prefix}/me` |
| `API_KEYS_ENABLED` | `false` | | | accept the keys of `API_KEYS` on both checks; while `false`, `API_KEYS` and `API_KEY_PERMISSIONS` are ignored |
| `API_KEYS` | empty | when enabled (at least one) | yes | `name:secret` entries (split at the first `:`); names and secrets unique, secrets at least 16 bytes and without `,` |
| `API_KEY_PERMISSIONS` | empty | | | `name=permission+permission` entries, e.g. `ci=builds:write+deployments:read,reader=*:read`; each name is a key of `API_KEYS` and appears once; a key without an entry has no permissions |

**Session**

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `SESSION_ENCRYPTION_KEY` | - | yes | yes | base64 of 32 bytes: `openssl rand -base64 32` |
| `SESSION_COOKIE_NAME` | `forwardauth_session` | not empty | | sent as `__Host-forwardauth_session` unless `SESSION_COOKIE_DOMAIN` or `SESSION_INSECURE_COOKIE` is set (a `__Host-` or `__Secure-` name of your own is kept and must fit its prefix) |
| `SESSION_COOKIE_DOMAIN` | empty | | | empty is a host-only cookie |
| `SESSION_INSECURE_COOKIE` | `false` | | | drops `Secure`; local HTTP development only; required for an `http` `EXTERNAL_URL` whose host is not loopback (`app.localhost` is not) |
| `SESSION_SAME_SITE` | `lax` | not empty | | `lax` or `none` (`none` for front-channel logout; not with an insecure cookie). `strict` is refused: the browser would withhold the cookie, and the login state with it, on the redirect back from the provider |
| `SESSION_MAXIMUM_AGE_SECONDS` | `86400` | | | absolute lifetime, at least 1; refreshes never extend it |
| `SESSION_REFRESH_INTERVAL_SECONDS` | `60` | | | how often the GitHub provider re-checks teams; at least 1 |
| `SESSION_MAXIMUM_UNVERIFIED_AGE_SECONDS` | `3600` | | | a team re-check failing (GitHub outage, rate limit) for longer than this since the last successful one ends the session; at least `SESSION_REFRESH_INTERVAL_SECONDS` |
| `SESSION_REDIS_ENABLED` | `false` | | | otherwise in-memory: exactly one replica |
| `SESSION_REDIS_ADDRESS` | empty | with Redis | | `host:port`; pinged at boot (5 s) |
| `SESSION_REDIS_PASSWORD` | empty | | yes | |
| `SESSION_REDIS_DATABASE` | `0` | | | at least 0 |
| `SESSION_REDIS_KEY_PREFIX` | `forwardauth` | not empty | | |

**OIDC (`PROVIDER=oidc`)**

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `OIDC_NAME` | `oidc` | not empty | | provider name, part of the route paths; `[a-z0-9-]{1,32}` |
| `OIDC_ISSUER` | empty | with `oidc` | | discovery at `<issuer>/.well-known/openid-configuration`; https (http only on loopback) |
| `OIDC_CLIENT_ID` | empty | with `oidc` | | |
| `OIDC_CLIENT_SECRET` | empty | with `oidc` | yes | |
| `OIDC_SCOPES` | `openid,profile,email` | not empty | | |
| `OIDC_CLAIM_MAPPER` | `default` | not empty | | `default` or `google` |
| `OIDC_ALLOWED_EMAIL_DOMAINS` | empty | | | requires `email_verified`; strongly recommended with Google |
| `OIDC_POST_LOGOUT_URL` | empty | | | empty means `EXTERNAL_URL/`; a path or an absolute URL without fragment |
| `OIDC_DISABLE_IFRAME_LOGOUT_DETECTION` | `false` | | | stop treating `Sec-Fetch-Dest: iframe` on `/logout` as front-channel logout; a cross-site iframe load of `/logout` is then refused (403) |

**Keycloak (optional, with `PROVIDER=oidc`)**

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `KEYCLOAK_ENABLED` | `false` | | | enrich identities through the Admin API; needs `PROVIDER=oidc` |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM` | empty | when enabled | | |
| `KEYCLOAK_AUTHENTICATION_REALM` | empty | | | realm the service account logs into (e.g. `master`); empty means `KEYCLOAK_REALM` |
| `KEYCLOAK_GRANT_TYPE` | `client_credentials` | not empty | | or `password` |
| `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | empty | client credentials | secret | |
| `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD` | empty | password grant | password | |
| `KEYCLOAK_CLIENT_ROLES_CLIENT_ID` | empty | | | client whose roles become client roles |
| `KEYCLOAK_REQUIRED_REALM_ROLES`, `KEYCLOAK_REQUIRED_CLIENT_ROLES`, `KEYCLOAK_REQUIRED_GROUPS` | empty | | | login is refused (403) when one is missing; groups are paths; required client roles need `KEYCLOAK_CLIENT_ROLES_CLIENT_ID` |

**GitHub (`PROVIDER=github`)**

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `GITHUB_CLIENT_ID` | empty | with `github` | | |
| `GITHUB_CLIENT_SECRET` | empty | with `github` | yes | |
| `GITHUB_ALLOWED_TEAMS` | empty | with `github` (at least one) | | `org/team-slug`, case-insensitive |
| `GITHUB_ADMIN_TEAMS` | empty | | | members of an allowed team get the `admin` role |
| `GITHUB_RELEVANT_TEAMS` | empty | | | extra teams kept in the identity |
| `GITHUB_SCOPES` | `read:org` | not empty | | must include `read:org`, `write:org`, `admin:org`, `user` or `repo` (the team lookup needs one) |
| `GITHUB_AUTHORIZE_URL` | `https://github.com/login/oauth/authorize` | not empty | | GitHub Enterprise |
| `GITHUB_TOKEN_URL` | `https://github.com/login/oauth/access_token` | not empty | | GitHub Enterprise |
| `GITHUB_API_URL` | `https://api.github.com` | not empty | | GitHub Enterprise, e.g. `https://ghe.example.com/api/v3`; no query or fragment |

**JWT**

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `JWT_ENABLED` | `false` | | | sign an identity token per allowed request |
| `JWT_PRIVATE_KEY` | empty | when enabled | yes | PEM RSA key, at least 2048 bits; no generated fallback, so every replica signs with the same key |
| `JWT_ISSUER` | empty | | | what backends configure as `Issuer`; empty means `EXTERNAL_URL` |
| `JWT_AUDIENCE` | empty | | | |
| `JWT_LIFETIME_SECONDS` | `300` | | | at least 1 |
| `JWT_HEADER` | `Authorization` | not empty | | value `Bearer <jwt>`; list the header in `authResponseHeaders`; a header name, not `Cache-Control`, `Set-Cookie`, `Connection`, `Content-Length` or `Transfer-Encoding` |

The token carries `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `provider`, `user_id`, `preferred_username`, `name`, `email`, `picture`, `roles`, `realm_roles`, `client_roles`, `groups`, `teams`, `permissions` (empty ones omitted) and every other claim of the OIDC ID token; ID token claims with these names (and `nonce`, `at_hash`, `c_hash`, `auth_time`, `sid`, `azp`) are never copied, so an IdP `roles` claim cannot become application roles. For GitHub, `sub` is the numeric user ID and the login is `preferred_username`. Verify it in your backend as shown in [Backend JWT verification](#backend-jwt-verification).

### Operations

- Logs are wide events: one JSON line per request on stdout, none for health. Readiness requests are sampled like any other (`WIDE_EVENT_SAMPLE_RATE`); a failed readiness check is always kept with its cause. Query values are redacted (callbacks carry `code` and `state`), also by the `DEV_MODE` emitter. Each event sums the request's outbound calls per dependency: `cache.calls`, `.failures`, `.duration_ms`, `.error` for Redis and `http.<oidc|keycloak|github>.calls`, `.failures`, `.duration_ms`, `.status`, `.error` for the provider (a transport error is recorded as cancellation, a dial error or its type, never with the URL or bytes the server sent). Unknown paths are recorded as failures (`no route`) and always kept by the sampler. Startup, shutdown and net/http's own error lines go through `log/slog` JSON.
- Metrics on `METRICS_PORT`: `forwardauth_http_requests_total{route,method,status}`, `forwardauth_http_request_duration_seconds{route,method}`, `forwardauth_http_requests_in_flight`, `forwardauth_auth_outcomes_total{provider,action,result}`, `forwardauth_dependency_request_duration_seconds{dependency,operation,outcome}` (Redis and the provider's HTTP calls), Go, process and build-info collectors.
- With `SESSION_REDIS_ENABLED` the boot fails when Redis does not answer within 5 s; the Redis client never retries a command.
- With `API_KEYS_ENABLED=true` the keys in `API_KEYS` are accepted on both check endpoints (not on `{prefix}/me`). Their identity carries the permissions from `API_KEY_PERMISSIONS` and no roles, so `authorization.IsAdmin` refuses them: check permissions in the backend (`HasPermission`, `RequireMethodPermission`). With API keys enabled, a request whose `Authorization: Bearer` value is not a configured key is refused with 401 `invalid_api_key` on both checks, even with a valid session cookie: an SPA that sends its own bearer tokens through the proxy cannot use API keys.
- With `JWT_ENABLED` an inactive identity is answered 403 (the token would come back active).
- Failures answer the one JSON shape (a panic is 500 `internal`); check answers carry `Cache-Control: no-store`.
- Both listeners bound every connection phase (read header 10 s, read 30 s, write 60 s, idle 120 s).

## Security notes

- **Cookie:** `HttpOnly`, `Secure` (unless `InsecureCookie`), `SameSite=Lax` by default, `Path=/`, host-only unless `CookieDomain` is set. The value is 32 random bytes; the backend key is its SHA-256. Session values are AES-256-GCM sealed with a key derived per session (HKDF-SHA256) from `EncryptionKey`, bound to the session ID and key. There is no signing key to leak.
- **Sessions:** the ID is rotated at every completed login (the previous session is revoked); starting an OIDC or GitHub login keeps a logged-in session, so a cross-site link to a login route ends nothing. Logout and failed refreshes revoke server-side, the lifetime is absolute (`MaximumAge` from the login), a lifetime starts only on a session the store issued itself (a planted or expired cookie, or a handle kept past its expiry, cannot get one), a revoked session never regains an identity and refuses writes while its revocation marker lives (a full memory backend may evict the marker), and a refresh never overwrites a change saved while it ran. Revoking an unknown session ID stores nothing. A Secure host-only cookie on path `/` (the default) is named `__Host-` + `CookieName`, so a sibling subdomain cannot toss a same-named cookie that would be read first. Changing `EncryptionKey` logs everyone out; there is no key rotation list.
- **OAuth flows:** `state`, `nonce` (OIDC) and the PKCE S256 verifier are random, stored server-side in the login session, valid for 10 minutes and single use. ID tokens are verified for signature, issuer, audience, expiry, nonce and subject. OIDC (including the endpoints discovery names), Keycloak and GitHub URLs must be `https` (loopback hosts excepted for tests). The library follows no redirect of these endpoints or a JWKS URL: a redirected call fails (`redirect refused`), because net/http would resend a token request's body (client secret, code, PKCE verifier) to the redirect's target, also over plain `http`. Discovery documents and key sets above 1 MiB are refused. The GitHub token is sent to the GitHub API host only. A token endpoint's error answer is recorded by its HTTP status and OAuth error code only, never its description or body; failed OIDC discovery requests and Keycloak Admin API answers by their status code only, and an ID token that does not verify by a fixed reason, never go-oidc's message (it quotes the token and the JWKS request's error).
- **Open redirects:** `return_to` is accepted only as a same-origin relative path (starts with `/`, not `//` or `/\`, valid UTF-8, no control characters, at most 2048 bytes); anything else becomes `/`. Redirects after login always go to `ExternalURL` plus that path. Configured targets (`LoginURL`, `ErrorURL`, `PostLogoutURL`) are validated at startup.
- **Errors:** responses carry fixed messages and stable codes. Errors of outbound HTTP calls name the method, the origin and a classified cause, never the path, query or bytes the server sent. Clients get a generic code and message; the reason (e.g. the missing Keycloak role) and a sanitized cause are recorded in the outcome and on the wide event, never in metric labels. Neither ever carries a credential or token.
- **Credentials:** unknown users cost the same Argon2id verification as real ones, and a stored hash nothing can verify answers like a wrong password at the same cost; API keys are compared as SHA-256 hashes in constant time without early exit; passwords are 1-128 bytes, default minimum length 12 characters. Each TOTP code is accepted once; wrong codes lock the second factor after `MaximumAttempts` in a row.
- **JWT:** RS512 only, key ID is the RFC 7638 thumbprint, default lifetime 5 minutes, minted per request, never cached, `exp` required, never for an inactive identity. The verifier ignores JWKS keys that are not RSA signing keys with an RS*/PS* `alg` and a `kid`, and its errors never repeat the JWKS answer. Backends must verify the signature and issuer; do not trust headers a client could set (see the Traefik settings above).
- **Known limits:** no rate limiting (do it at Traefik, at least on the password login and TOTP routes), no retries, no idle timeout. The memory backend is for one replica at non-production scale; use Redis in production. Logout CSRF is refused only by browsers that send `Sec-Fetch-Site` (all current ones); OIDC front-channel logout stays callable cross-site by design. A stale `SaveIdentity` from your own code (impersonation) racing a Guard refresh still overwrites it; use `Session.SwapIdentity` (saves only while the session still holds the identity you read) where that matters.

## Release notes

### v1.0.0

First release of `github.com/govengers/auth`. It merges `mxcd/go-basicauth` (v1.5.x), `mxcd/oidc-fwd-auth` (v0.9.x) and `mxcd/github-fwd-auth` (v1.4.x) into one module and adds authorization checks, resource permissions, API keys, a gin and a Prometheus adapter, a Redis session backend and the forward-auth image. There are no compatibility shims; [docs/migration.md](docs/migration.md) maps every old symbol and environment variable and gives a recipe per library.

Breaking changes against all three predecessors:

- New import path `github.com/govengers/auth/...`; Go 1.26.
- Sessions are server-side for every provider; the cookie holds a random ID only; the lifetime is `StoreOptions.MaximumAge` (`Store.MaximumAge()`, `SESSION_MAXIMUM_AGE_SECONDS`). **Existing sessions are invalid: every user logs in once after the upgrade.** The cookie-only mode, `gorilla/sessions` and the signing keys are gone; one 32-byte `EncryptionKey` remains (`openssl rand -base64 32`). An own `session.Backend` implements five methods, `CompareAndSwap` included; `ErrSessionRevoked` is `session.ErrRevoked`.
- One identity type, `auth.Identity`, replaces `basicauth.User`, `oidc.SessionData`, `jwt.User` and the GitHub session user. One `session.Guard` replaces the per-provider middleware; there is no global middleware and no `PathRules`, you mount the Guard on route groups.
- Route prefixes: `/auth/password/*`, `/auth/oidc/<name>/*`, `/auth/github/*`, each a `PathPrefix` of plain segments without a trailing `/`. Redirect URIs are derived from `ExternalURL`; register the new callback URLs at your IdP and GitHub. `ErrorURL` and `PostLogoutURL` become absolute and refuse fragments.
- One error body `{"code","message"}` with stable codes (`tfa_*` became `totp_*`, `unauthorized` became `unauthenticated`); translated `Messages` are gone.
- Hooks are `auth.Hook` (`OnLogin`) and `auth.LogoutHook`; `UserTransformer` is an application middleware after the Guard. Libraries no longer log; they call an optional `auth.Observer`.
- `password`: default minimum length 12 characters without composition rules; `Storage` takes a `context.Context`, gains `UpdatePasswordHash` (compare-and-swap), `ConsumeTOTPStep` (a `totp_step` column; every TOTP code is accepted once) and `ErrUserExists`, matches usernames and emails ignoring case, and `SetTOTP` returns `(bool, error)`: it enables TOTP only while it is off, atomically (`... WHERE id = $1 AND NOT totp_enabled`); `OnLogin` must keep `UserID`; `TOTP.Required` enrolls during login and registration; TOTP routes exist only with `TOTP.Enabled`, and enrolled users cannot log in while it is off; backup codes are checked only with `"backupCode": true` (no fallthrough from a wrong TOTP code); `MaximumAttempts` is a lockout across logins until a verified code or `ResetTOTPAttempts`, with no unlimited mode; new limits `Period` <= 3600, `Skew` <= 10, `BackupCodeCount` <= 20, backup codes <= 128 bytes and >= 1,000,000 distinct codes; Argon2id hashes on outdated parameters are rehashed at login.
- OIDC and GitHub: PKCE (and nonce) always on, GitHub logout is `GET`, logout (also password logout) refuses `Sec-Fetch-Site: cross-site` with 403, so logout links must live on the app's own site, GitHub `AllowedTeams` is required (an empty list no longer admits everyone), GitHub `Scopes` must include one that lists teams (`read:org`, `write:org`, `admin:org`, `user`, `repo`), the endpoints OIDC discovery names must be `https` (or loopback `http`), no component follows a redirect of its token, discovery, JWKS, Keycloak, GitHub revocation or GitHub user and team endpoint (point the URLs at the final location), Keycloak enrichment moved from gocloak to `oidc/keycloak` and defaults to client credentials, GitHub `UserProfile` and friends are gone (`Identity.Teams`, `HTTPClient`).
- API keys are named, at least 16 bytes, unique, and grant only the roles and permissions you give them (the old "API key bypasses admin" behaviour needs `Roles: []string{auth.RoleAdmin}`). `Authorization: Bearer` is matched in any case, so a foreign bearer token on a route behind `apikey` is 401.
- JWT: RS512 only, jwx v3, `exp` required, default lifetime 5 minutes (was 30), issuer defaults to `EXTERNAL_URL`, GitHub `sub` is the numeric user ID and the login is `preferred_username` (`uid` is gone), JWKS at `/auth/jwks`, no generated signing key, `Sign` refuses an inactive identity, the verifier uses only RSA JWKS keys with an RS*/PS* `alg` and a `kid` and answers 401 with `WWW-Authenticate: Bearer`.
- Forward-auth: one image `ghcr.io/govengers/forwardauth` selected by `PROVIDER` replaces `oidc-fwd-auth` and `github-fwd-auth`; renamed environment variables, new routes (`/auth/ui`, `/auth/api`, `/auth/jwks`), an explicit Traefik router for `/auth` (without the checks and probes) is required, Google multi-provider mode is removed, `JWT_PRIVATE_KEY` is required when JWT is on, API keys need `API_KEYS_ENABLED=true` (`API_KEYS` alone is ignored) and carry permissions (`API_KEY_PERMISSIONS`) but no roles. `EXTERNAL_URL` is an origin without a path, a route with a trailing `/` is 404 (no redirect), `SESSION_SAME_SITE` takes `lax` or `none`, `SHUTDOWN_DELAY_SECONDS` at most 10, the boot fails when Redis does not answer or when a plain `http` `EXTERNAL_URL` off loopback comes without `SESSION_INSECURE_COOKIE=true`; list `X-API-Key` next to `Authorization` in `authResponseHeaders`.

New: `authorization` (incl. `HasPermission`), resource permissions (`auth.Permission`, `ginadapter.RequireMethodPermission`, the JWT `permissions` claim), `apikey`, `ginadapter`, `prometheusadapter`, `session/redisbackend`, TOTP enrollment during login, `Refresher`s that re-check teams and users every minute, `IdentityHandler`, wide-event and Prometheus reporting in the image.

## Contributing

`just check` runs lint, unit tests with `-race` and an 80 % coverage gate (total and per package), both end-to-end suites and `govulncheck`; `just docker-build` builds the image. Code follows the [govengers standards](https://github.com/govengers/standards) with the `library` profile (`.govengers.yml`; one waived rule, DES-008, for the password provider's single `identifier` field, reason in the file). The repository also contains a service: reviewers additionally apply the service rules (CFG, LAY, LOG, MET, DEP, API-001, API-002) to `cmd/forwardauth` and `internal/forwardauth`. The design and decision log are in [docs/design.md](docs/design.md), CI, image and e2e details in [docs/infrastructure-notes.md](docs/infrastructure-notes.md). Releases: push a `vX.Y.Z` tag; the release workflow publishes the image. After the very first push the GHCR package must be made public once by hand (package settings; there is no API for it).

## License

[Apache 2.0](LICENSE)
