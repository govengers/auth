# auth

[![CI](https://github.com/govengers/auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![unit tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/unit-tests.json)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![e2e tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/e2e-tests.json)](test/e2e)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/coverage.json)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/govengers/auth.svg)](https://pkg.go.dev/github.com/govengers/auth)
[![License](https://img.shields.io/github/license/govengers/auth)](LICENSE)

Authentication and authorization for Go services, plus a forward-auth proxy image for Traefik.

Every provider (password, OIDC incl. Keycloak, GitHub OAuth, API key, JWT) produces the same `auth.Identity`. Redirect and password logins store it in one server-side session (the cookie carries a random ID only). One `session.Guard` turns a request with a session into a request with an identity in its `context.Context`, or refuses it: 401 JSON for APIs, 302 to the login URL for UIs. Authorization is a plain `func(context.Context) error` over that identity. The core packages are `net/http` only; gin, the wide-event logger and Prometheus stay in adapter packages. It replaces `mxcd/go-basicauth`, `mxcd/oidc-fwd-auth` and `mxcd/github-fwd-auth` ([migration guide](docs/migration.md)).

## Installation

```bash
go get github.com/govengers/auth@v1
```

One module, one package per provider. A program that imports `password` compiles neither gin, go-oidc nor Redis.

| Package | Purpose | Heavy dependency |
|---|---|---|
| `auth` | `Identity`, context helpers, `Error` and the one JSON error shape, `Observer`, `Hook`, `Route`, `IdentityHandler` | - |
| `session` | server-side sessions: `Store`, `Backend`, `MemoryBackend`, `Guard` (`RequireAPI`, `RequireUI`), `Refresher`, `ParseKey` | - |
| `session/redisbackend` | `session.Backend` on Redis (client, sentinel or cluster) | go-redis |
| `password` | username/email + password (Argon2id), TOTP with backup codes, registration, legacy bcrypt upgrade; you implement `Storage` | x/crypto, otp |
| `oidc` | OIDC code flow with PKCE and nonce, RP-initiated and front-channel logout, claim mappers (Google) | go-oidc |
| `oidc/keycloak` | Keycloak Admin API enrichment (roles, groups, attributes, required roles) as an `OnLogin` hook | - |
| `github` | GitHub OAuth with PKCE, allowed/admin/relevant teams, token kept server-side, team refresh | - |
| `apikey` | static hashed API keys and a resolver for keys you issue | - |
| `jwt` | RS512 `Signer` with JWKS endpoint, JWKS `Verifier` with middleware | jwx v3 |
| `authorization` | `Check` combinators (`All`, `Any`, `Not`, `Real`) and primitives (`IsAdmin`, `HasRole`, ...) | - |
| `ginadapter` | `net/http` middleware and routes on gin, `Require` for checks, wide-event `Observe` | gin, go-wide-event-logger |
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

Constructors take an options pointer, validate it, copy what they keep and never write to your struct. Components never log and never start goroutines; they report outcomes to an optional `auth.Observer`. Errors are `*auth.Error` and answer with one shape, `{"code","message"}`; branch with `errors.Is(err, auth.ErrUnauthenticated | auth.ErrForbidden | auth.ErrInvalidRequest | auth.ErrConflict)`.

## Password login

Users live in your database behind `password.Storage`; `password.NewMemoryStorage()` is for tests and examples.

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/govengers/auth"
	"github.com/govengers/auth/password"
	"github.com/govengers/auth/session"
)

func main() {
	store := newStore(must(session.NewMemoryBackend(nil))) // one replica; Redis below
	provider := must(password.New(&password.Options{
		Sessions: store,
		Storage:  password.NewMemoryStorage(),
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
curl -c jar -H 'Content-Type: application/json' -d '{"identifier":"alice","password":"..."}' localhost:8080/auth/password/login
curl -b jar localhost:8080/api/hello
```

The provider reads sessions itself, so its routes need no Guard. All bodies are JSON.

| Route | Answer |
|---|---|
| `POST /auth/password/login` `{"identifier","password"}` | 200 identity, or 202 `{"challenge":"totp"}` / `{"challenge":"totp_setup"}` |
| `POST /auth/password/totp/verify` `{"code","backupCode"}` | 200 identity |
| `GET /auth/password/totp` | 200 `{"enabled"}` |
| `POST /auth/password/totp/setup`, `/enable`, `/disable` | setup secret and otpauth URL; backup codes; 204 |
| `POST /auth/password/register` (only with `EnableRegistration`) | 201 identity |
| `POST /auth/password/logout` | 204 |

`TOTP.Required` enrolls users who have no second factor during login (the 202 `totp_setup` challenge) instead of failing every route. Stable client codes (see [Errors](#errors)) replace translated messages. Existing Argon2id hashes verify unchanged; `LegacyVerifier: password.VerifyBcrypt` upgrades bcrypt hashes on the next login.

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

- Register `https://app.example.com/auth/oidc/keycloak/callback` at the IdP. The redirect URI is derived from `ExternalURL` and `PathPrefix`, the end-session endpoint is discovered.
- `RequireUI` answers 302 to `<login>?return_to=<path>`; the user returns to the original path after login. Use `RequireAPI` for JSON endpoints.
- `Enrich` replaces roles, client roles, groups (paths) and attributes with the Admin API's answer and refuses the login (403, role name stays server-side) when a required role or group is missing. Give the service account the `realm-management` roles `view-users`, `query-users`, `view-clients`, `query-clients`, `query-groups`. The default grant is `client_credentials`; the `password` grant breaks as soon as the admin user gets an OTP credential.
- Without Keycloak, roles and groups come from the access token (`realm_access.roles`, `resource_access.<client>.roles`) and ID token (`groups`).
- Google: `Issuer: "https://accounts.google.com"`, `ClaimMapper: oidc.GoogleClaimMapper`, and set `AllowedEmailDomains` (requires `email_verified`), otherwise any Google account gets in.
- One `oidc.New` per identity provider, distinct `Name`s, one shared `Store`. `ErrorURL` redirects callback refusals to `ErrorURL?code=<code>` instead of JSON.
- Front-channel logout needs `StoreOptions.SameSite: http.SameSiteNoneMode` (HTTPS only).

## GitHub login with teams

```go
provider := must(github.New(&github.Options{
	ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
	ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	ExternalURL:  "https://app.example.com",
	AllowedTeams: []string{"acme/engineering"}, // required, "org/team-slug", case-insensitive
	AdminTeams:   []string{"acme/platform"},    // members get auth.RoleAdmin
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

Imports are `github.com/govengers/auth/github` (package `github`) and the packages above. Register `https://app.example.com/auth/github/callback` as the OAuth app's callback URL. Users outside `AllowedTeams` get 403 and no session; a user removed from every allowed team loses the session at the next refresh. `Identity.Teams` holds only teams in the allowed, admin and relevant lists (`RelevantTeams`), lower-case. The GitHub token never leaves the server: call the GitHub API as the user with `provider.HTTPClient(ctx, session)` (`session` from `store.Open(request)`). GitHub Enterprise: set `AuthorizeURL`, `TokenURL` and `APIURL`.

Run it as a forward-auth proxy instead of a library with `PROVIDER=github` ([image](#forward-auth-image)).

## Backend JWT verification

The forward-auth image (and any `jwt.Signer`) mints a short-lived RS512 token per request. A backend verifies it against the JWKS endpoint and gets an `auth.Identity` without sessions:

```go
verifier := must(jwt.NewVerifier(ctx, &jwt.VerifierOptions{ // fetches the JWKS once, fails fast
	JWKSURL:  "http://forwardauth:8080/auth/jwks", // may be the internal address
	Issuer:   "https://app.example.com",           // JWT_ISSUER of the proxy, default EXTERNAL_URL
	Audience: "orders-api",                        // optional
}))

mux := http.NewServeMux()
mux.Handle("GET /orders", verifier.Middleware()(http.HandlerFunc(orders))) // 401 JSON when missing or invalid

// or in gin
ordersGroup := engine.Group("/orders", ginadapter.Middleware(verifier.Middleware()), ginadapter.Require(authorization.HasOIDCRole("orders")))
```

`Verify(ctx, token)` checks signature (algorithm must match the key), `iss`, `aud`, `exp` and `nbf` (30 s skew) and returns the identity: `sub` is `Subject`, `preferred_username` is `Username`, `realm_roles`, `client_roles`, `groups`, `teams`, `roles`, `user_id` fill the matching fields, and `Claims` holds all claims. Unknown key IDs trigger a JWKS refetch at most once a minute. There is no token cache and no goroutine. Do not put `apikey` middleware in front of the verifier: both read `Authorization: Bearer`.

## Authorization

A `Check` allows with `nil` and refuses with an `*auth.Error` (401 without identity, 403 otherwise). Primitives: `IsAuthenticated`, `IsActive`, `IsUser`, `IsAdmin`, `HasRole`, `HasUserID`, `HasOIDCRole`, `HasOIDCGroup`, `HasGitHubTeam`. Combinators: `All` (first refusal), `Any`, `Not` (never admits anonymous requests), `Real` (evaluates against the real identity while someone impersonates another).

```go
editors := authorization.Any(
	authorization.IsAdmin(),
	authorization.All(
		authorization.HasOIDCRole("editor"),
		authorization.Not(authorization.HasOIDCGroup("/contractors")),
	),
)

api := engine.Group("/api", ginadapter.Middleware(guard.RequireAPI()))
api.PUT("/articles/:id", ginadapter.Require(editors), updateArticle) // 401/403/500 JSON, recorded on the wide event

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

Your own code returns `&auth.Error{Kind: auth.ErrForbidden, Code: "plan_limit", Reason: "..."}`: `Code` replaces the default code, `Reason` and the wrapped cause never reach the client.

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

After `ginadapter.Middleware(...)` calls its next handler, `c.Request` is the enriched request, so later gin handlers and middleware see the identity. If the wrapped middleware refuses, the chain is aborted. `IdentityResponse` never exposes `Claims`, `Attributes` or `Data`.

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

// In main: Guard first, then WithUser.
protected := func(next http.Handler) http.Handler { return guard.RequireAPI()(WithUser(users)(next)) }
```

The password provider sets `UserID` itself. For OIDC and GitHub, provision the user at login in `OnLogin` so the identity carries your user ID:

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

In gin, use `ginadapter.Middleware(WithUser(users))` after `ginadapter.Middleware(guard.RequireAPI())`. A hook cannot add your user object to the context, which is why this is a middleware.

## API keys

```go
keys := must(apikey.New(&apikey.Options{
	Keys: []apikey.Key{{Name: "ci", Secret: os.Getenv("CI_API_KEY"), Roles: []string{auth.RoleAdmin}}}, // secret >= 16 bytes
}))
mux.Handle("GET /api/hello", keys.Middleware()(guard.RequireAPI()(hello)))
```

Keys come from `X-API-Key` or `Authorization: Bearer`. No key passes through to the Guard; a wrong key is 401 and never falls through. Keys you issue yourself (per user, revocable) go in `Resolver`. The identity's `Subject` and `Username` are the key name.

## Several replicas

The memory backend is correct for exactly one replica and forgets sessions on restart. For more, share one Redis and one `EncryptionKey`:

```go
client := redis.NewClient(&redis.Options{Addr: "redis:6379"}) // github.com/redis/go-redis/v9; you own and close it
defer client.Close()

backend := must(redisbackend.New(&redisbackend.Options{Client: client, KeyPrefix: "myapp"}))
store := newStore(backend)
```

`redisbackend` takes any `redis.UniversalClient` (client, sentinel, cluster; keys carry a hash tag). Logout and session rotation revoke on every replica, and a revoked session cannot be written again. To use another database, implement the four-method `session.Backend` (`Put`, `Get`, `Pop`, `Revoke`). A Redis dump holds SHA-256 hashes of session IDs and AES-256-GCM ciphertext, not usable cookies.

## Forward-auth image

`ghcr.io/govengers/forwardauth:<version>` (distroless, non-root, ports 8080 and 9090) runs one provider, `PROVIDER=oidc` or `PROVIDER=github`, in front of any app behind Traefik. Traefik calls `GET /auth/ui` (browsers) or `GET /auth/api` (APIs) for each request. 200 lets the request through, with a signed JWT in `Authorization` when `JWT_ENABLED`; anything else (302 to the login, 401, 403) goes to the client. Password login is not offered (Traefik's `basicAuth` covers static users). One instance serves one external origin. Without Redis it is a single replica.

### Quick start (docker compose)

```yaml
services:
  traefik:
    image: traefik:v3.4
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
    ports: ["80:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]

  forwardauth:
    image: ghcr.io/govengers/forwardauth:1.0.0
    environment:
      PROVIDER: oidc
      EXTERNAL_URL: https://app.example.com
      SESSION_ENCRYPTION_KEY: ${SESSION_ENCRYPTION_KEY}   # openssl rand -base64 32
      OIDC_ISSUER: https://keycloak.example.com/realms/example
      OIDC_CLIENT_ID: app
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      JWT_ENABLED: "true"
      JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY}                 # export JWT_PRIVATE_KEY="$(cat jwt.pem)"
    labels:
      - traefik.enable=true
      # the auth router must not carry the forwardAuth middleware; its longer rule wins
      - traefik.http.routers.app-auth.rule=Host(`app.example.com`) && PathPrefix(`/auth`)
      - traefik.http.routers.app-auth.service=forwardauth
      - traefik.http.services.forwardauth.loadbalancer.server.port=8080
      # UI variant: unauthenticated browsers are redirected to the login
      - traefik.http.middlewares.forwardauth-ui.forwardauth.address=http://forwardauth:8080/auth/ui
      - traefik.http.middlewares.forwardauth-ui.forwardauth.authResponseHeaders=Authorization
      # API variant: unauthenticated clients get 401 JSON
      - traefik.http.middlewares.forwardauth-api.forwardauth.address=http://forwardauth:8080/auth/api
      - traefik.http.middlewares.forwardauth-api.forwardauth.authResponseHeaders=Authorization

  app:
    image: traefik/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.app.rule=Host(`app.example.com`)
      - traefik.http.routers.app.middlewares=forwardauth-ui
      - traefik.http.routers.app-api.rule=Host(`app.example.com`) && PathPrefix(`/api`)
      - traefik.http.routers.app-api.middlewares=forwardauth-api
```

Generate the JWT key with `openssl genrsa -out jwt.pem 3072` (PKCS#1 or PKCS#8 PEM, at least 2048 bits). Register `https://app.example.com/auth/oidc/oidc/callback` (`<EXTERNAL_URL><PATH_PREFIX>/oidc/<OIDC_NAME>/callback`) at the IdP, or `https://app.example.com/auth/github/callback` for GitHub. Behind plain HTTP in development set `SESSION_INSECURE_COOKIE=true`.

Kubernetes, with the Traefik CRDs:

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
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: app
  namespace: default
spec:
  routes:
    - match: Host(`app.example.com`) && PathPrefix(`/auth`)   # no middleware here
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

Set `GOMEMLIMIT` 5-10 % below the container memory limit in your manifests (limit 256Mi, `GOMEMLIMIT=230MiB`); Go reads the CPU limit itself. The default termination grace period of 30 s covers the shutdown (readiness 503 for `SHUTDOWN_DELAY_SECONDS`, then a 20 s drain).

### Routes

`{prefix}` is `PATH_PREFIX` (default `/auth`).

| Route | Purpose |
|---|---|
| `GET {prefix}/ui` | forward-auth check for browsers: 302 to the login when unauthenticated |
| `GET {prefix}/api` | forward-auth check for APIs: 401 JSON when unauthenticated |
| `GET {prefix}/jwks` | public keys of the JWT signer (`JWT_ENABLED`) |
| `GET {prefix}/me` | the caller's identity as JSON (`IDENTITY_ENDPOINT_ENABLED`) |
| `GET {prefix}/health`, `GET {prefix}/ready` | liveness; readiness (503 during shutdown or when the Redis ping fails) |
| `GET {prefix}/oidc/<OIDC_NAME>/{login,callback,logout,frontchannel-logout}` | OIDC provider |
| `GET {prefix}/github/{login,callback,logout}`, `POST {prefix}/github/refresh-teams` | GitHub provider |
| `GET /metrics` on `METRICS_PORT` | Prometheus; keep this port off Traefik |

Route `{prefix}` to the service with its own Traefik router, as in the labels above: the check endpoints do not dispatch login routes by `X-Forwarded-Uri`. Link users to `{prefix}/oidc/<name>/logout` or `{prefix}/github/logout` to log out; both are plain `GET` links.

### Environment variables

Values without a default are required. The process exits non-zero before it starts and lists every missing or invalid value (a bad `EXTERNAL_URL`, `PATH_PREFIX` or `SESSION_SAME_SITE`, an API key without a name, a missing Keycloak setting). Sensitive values are masked in the startup table. A `.env` file in the working directory is read if present (development only; the image has none).

**General**

| Variable | Default | Required | Notes |
|---|---|---|---|
| `PROVIDER` | - | yes | `oidc` or `github` |
| `EXTERNAL_URL` | - | yes | public base URL of the protected app, e.g. `https://app.example.com` |
| `PATH_PREFIX` | `/auth` | | prefix of every route; starts with `/`, no trailing `/` |
| `PORT` | `8080` | | public listener |
| `METRICS_PORT` | `9090` | | `/metrics` listener |
| `DEV_MODE` | `false` | | development wide-event emitter, gin debug mode |
| `WIDE_EVENT_SAMPLE_RATE` | `10` | | keep every Nth successful event; failures, 401, 403 and degraded events are always kept |
| `SHUTDOWN_DELAY_SECONDS` | `5` | | readiness 503 this long before draining |
| `IDENTITY_ENDPOINT_ENABLED` | `false` | | mounts `{prefix}/me` |
| `API_KEYS` | empty | | comma-separated `name:secret` (split at the first `:`); secret at least 16 bytes and without `,` |

**Session**

| Variable | Default | Required | Notes |
|---|---|---|---|
| `SESSION_ENCRYPTION_KEY` | - | yes | base64 of 32 bytes: `openssl rand -base64 32` (sensitive) |
| `SESSION_COOKIE_NAME` | `forwardauth_session` | | |
| `SESSION_COOKIE_DOMAIN` | empty | | empty is a host-only cookie |
| `SESSION_INSECURE_COOKIE` | `false` | | drops `Secure`; local HTTP development only |
| `SESSION_SAME_SITE` | `lax` | | `lax`, `strict` or `none` (`none` for front-channel logout; not with an insecure cookie) |
| `SESSION_MAX_AGE_SECONDS` | `86400` | | absolute lifetime; refreshes never extend it |
| `SESSION_REFRESH_INTERVAL_SECONDS` | `60` | | how often the GitHub provider re-checks teams |
| `SESSION_REDIS_ENABLED` | `false` | | otherwise in-memory: exactly one replica |
| `SESSION_REDIS_ADDRESS` | empty | with Redis | `host:port` |
| `SESSION_REDIS_PASSWORD` | empty | | sensitive |
| `SESSION_REDIS_DATABASE` | `0` | | |
| `SESSION_REDIS_KEY_PREFIX` | `forwardauth` | | |

**OIDC (`PROVIDER=oidc`)**

| Variable | Default | Required | Notes |
|---|---|---|---|
| `OIDC_NAME` | `oidc` | | provider name, part of the route paths |
| `OIDC_ISSUER` | empty | yes | discovery at `<issuer>/.well-known/openid-configuration` |
| `OIDC_CLIENT_ID` | empty | yes | |
| `OIDC_CLIENT_SECRET` | empty | yes | sensitive |
| `OIDC_SCOPES` | `openid,profile,email` | | |
| `OIDC_CLAIM_MAPPER` | `default` | | `default` or `google` |
| `OIDC_ALLOWED_EMAIL_DOMAINS` | empty | | requires `email_verified`; strongly recommended with Google |
| `OIDC_POST_LOGOUT_URL` | empty | | empty means `EXTERNAL_URL/` |
| `OIDC_DISABLE_IFRAME_LOGOUT_DETECTION` | `false` | | stop treating `Sec-Fetch-Dest: iframe` on `/logout` as front-channel logout |

**Keycloak (optional, with `PROVIDER=oidc`)**

| Variable | Default | Required | Notes |
|---|---|---|---|
| `KEYCLOAK_ENABLED` | `false` | | enrich identities through the Admin API |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM` | empty | when enabled | |
| `KEYCLOAK_AUTHENTICATION_REALM` | empty | | realm the service account logs into (e.g. `master`); empty means `KEYCLOAK_REALM` |
| `KEYCLOAK_GRANT_TYPE` | `client_credentials` | | or `password` |
| `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | empty | client credentials | secret is sensitive |
| `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD` | empty | password grant | password is sensitive |
| `KEYCLOAK_CLIENT_ROLES_CLIENT_ID` | empty | | client whose roles become client roles |
| `KEYCLOAK_REQUIRED_REALM_ROLES`, `KEYCLOAK_REQUIRED_CLIENT_ROLES`, `KEYCLOAK_REQUIRED_GROUPS` | empty | | login is refused (403) when one is missing; groups are paths |

**GitHub (`PROVIDER=github`)**

| Variable | Default | Required | Notes |
|---|---|---|---|
| `GITHUB_CLIENT_ID` | empty | yes | |
| `GITHUB_CLIENT_SECRET` | empty | yes | sensitive |
| `GITHUB_ALLOWED_TEAMS` | empty | yes (at least one) | `org/team-slug`, case-insensitive |
| `GITHUB_ADMIN_TEAMS` | empty | | members get the `admin` role |
| `GITHUB_RELEVANT_TEAMS` | empty | | extra teams kept in the identity |
| `GITHUB_SCOPES` | `read:org` | | |
| `GITHUB_AUTHORIZE_URL` | `https://github.com/login/oauth/authorize` | | GitHub Enterprise |
| `GITHUB_TOKEN_URL` | `https://github.com/login/oauth/access_token` | | GitHub Enterprise |
| `GITHUB_API_URL` | `https://api.github.com` | | GitHub Enterprise, e.g. `https://ghe.example.com/api/v3` |

**JWT**

| Variable | Default | Required | Notes |
|---|---|---|---|
| `JWT_ENABLED` | `false` | | sign an identity token per allowed request |
| `JWT_PRIVATE_KEY` | empty | when enabled | PEM RSA key, at least 2048 bits; no generated fallback, so every replica signs with the same key (sensitive) |
| `JWT_ISSUER` | empty | | what backends configure as `Issuer`; empty means `EXTERNAL_URL` |
| `JWT_AUDIENCE` | empty | | |
| `JWT_LIFETIME_SECONDS` | `300` | | |
| `JWT_HEADER` | `Authorization` | | value `Bearer <jwt>`; list the header in `authResponseHeaders` |

The token carries `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `provider`, `user_id`, `preferred_username`, `name`, `email`, `picture`, `roles`, `realm_roles`, `client_roles`, `groups`, `teams` (empty ones omitted) and every other claim of the OIDC ID token. For GitHub, `sub` is the numeric user ID and the login is `preferred_username`. Verify it in your backend as shown in [Backend JWT verification](#backend-jwt-verification).

### Operations

- Logs are wide events: one JSON line per request on stdout, none for health and readiness. Query values are redacted (callbacks carry `code` and `state`). Startup and shutdown lines go through `log/slog` JSON.
- Metrics on `METRICS_PORT`: `forwardauth_http_requests_total{route,method,status}`, `forwardauth_http_request_duration_seconds{route,method}`, `forwardauth_http_requests_in_flight`, `forwardauth_auth_outcomes_total{provider,action,result}`, Go, process and build-info collectors.
- API keys in `API_KEYS` are accepted on both check endpoints and carry no roles.

## Security notes

- **Cookie:** `HttpOnly`, `Secure` (unless `InsecureCookie`), `SameSite=Lax` by default, `Path=/`, host-only unless `CookieDomain` is set. The value is 32 random bytes; the backend key is its SHA-256. Session values are AES-256-GCM sealed, bound to the session ID and key. There is no signing key to leak.
- **Sessions:** the ID is rotated at every login (the previous session is revoked), logout and failed refreshes revoke server-side, the lifetime is absolute (`MaxAge` from the first login), and a revoked session cannot be written again. Changing `EncryptionKey` logs everyone out; there is no key rotation list.
- **OAuth flows:** `state`, `nonce` (OIDC) and the PKCE S256 verifier are random, stored server-side in the login session, valid for 10 minutes and single use. ID tokens are verified for signature, issuer, audience, expiry and nonce. OIDC and GitHub URLs must be `https` (loopback hosts excepted for tests).
- **Open redirects:** `return_to` is accepted only as a same-origin relative path (starts with `/`, not `//` or `/\`, no control characters, at most 2048 bytes); anything else becomes `/`. Redirects after login always go to `ExternalURL` plus that path.
- **Errors:** responses carry fixed messages and stable codes. Required role, team and domain names, causes and tokens stay in server-side `Reason`s and are never sent or put into outcomes, wide events or metric labels.
- **Credentials:** unknown users cost the same Argon2id verification as real ones; API keys are compared as SHA-256 hashes in constant time without early exit; passwords are 1-128 bytes, default minimum length 12.
- **JWT:** RS512 only, key ID is the RFC 7638 thumbprint, default lifetime 5 minutes, minted per request, never cached. Backends must verify the signature and issuer; do not trust headers a client could set.
- **Known limits:** no rate limiting (do it at Traefik), no retries, TOTP codes can be replayed inside one period, logout by `GET` can be triggered cross-site (it only ends the victim's session), no idle timeout.

## Release notes

### v1.0.0

First release of `github.com/govengers/auth`. It merges `mxcd/go-basicauth` (v1.5.x), `mxcd/oidc-fwd-auth` (v0.9.x) and `mxcd/github-fwd-auth` (v1.4.x) into one module and adds authorization checks, API keys, a gin and a Prometheus adapter, a Redis session backend and the forward-auth image. There are no compatibility shims; [docs/migration.md](docs/migration.md) maps every old symbol and environment variable and gives a recipe per library.

Breaking changes against all three predecessors:

- New import path `github.com/govengers/auth/...`; Go 1.26.
- Sessions are server-side for every provider; the cookie holds a random ID only. **Existing sessions are invalid: every user logs in once after the upgrade.** The cookie-only mode, `gorilla/sessions` and the signing keys are gone; one 32-byte `EncryptionKey` remains (`openssl rand -base64 32`).
- One identity type, `auth.Identity`, replaces `basicauth.User`, `oidc.SessionData`, `jwt.User` and the GitHub session user. One `session.Guard` replaces the per-provider middleware; there is no global middleware and no `PathRules`, you mount the Guard on route groups.
- Route prefixes: `/auth/password/*`, `/auth/oidc/<name>/*`, `/auth/github/*`. Redirect URIs are derived from `ExternalURL`; register the new callback URLs at your IdP and GitHub.
- One error body `{"code","message"}` with stable codes (`tfa_*` became `totp_*`, `unauthorized` became `unauthenticated`); translated `Messages` are gone.
- Hooks are `auth.Hook` (`OnLogin`) and `auth.LogoutHook`; `UserTransformer` is an application middleware after the Guard. Libraries no longer log; they call an optional `auth.Observer`.
- `password`: default minimum length 12 without composition rules, `Storage` takes a `context.Context` and gains `UpdatePasswordHash` (compare-and-swap) and `ErrUserExists`, `TOTP.Required` enrolls during login.
- OIDC and GitHub: PKCE (and nonce) always on, GitHub logout is `GET`, Keycloak enrichment moved from gocloak to `oidc/keycloak` and defaults to client credentials, GitHub `UserProfile` and friends are gone (`Identity.Teams`, `HTTPClient`).
- JWT: RS512 only, jwx v3, default lifetime 5 minutes (was 30), issuer defaults to `EXTERNAL_URL`, GitHub `sub` is the numeric user ID, JWKS at `/auth/jwks`, no generated signing key.
- Forward-auth: one image `ghcr.io/govengers/forwardauth` selected by `PROVIDER` replaces `oidc-fwd-auth` and `github-fwd-auth`; renamed environment variables, new routes (`/auth/ui`, `/auth/api`, `/auth/jwks`), an explicit Traefik router for `/auth` is required, Google multi-provider mode is removed, `JWT_PRIVATE_KEY` is required when JWT is on.

New: `authorization`, `apikey`, `ginadapter`, `prometheusadapter`, `session/redisbackend`, TOTP enrollment during login, `Refresher`s that re-check teams and users every minute, `IdentityHandler`, wide-event and Prometheus reporting in the image.

## Contributing

`just check` runs lint, unit tests with `-race` and an 80 % coverage gate, both end-to-end suites and `govulncheck`; `just docker-build` builds the image. Code follows the [govengers standards](https://github.com/govengers/standards) with the `library` profile (`.govengers.yml`, no waived rules). The repository also contains a service: reviewers additionally apply the service rules (CFG, LAY, LOG, MET, DEP, API-001, API-002) to `cmd/forwardauth` and `internal/forwardauth`. The design and decision log are in [docs/design.md](docs/design.md).

## License

[Apache 2.0](LICENSE)
