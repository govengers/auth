# govengers/auth

Authentication and authorization for Go services on `net/http` (gin through an adapter), plus a forward-auth proxy image for Traefik. Module `github.com/govengers/auth`, Go 1.26, Apache 2.0.

## Model

Every provider produces one `auth.Identity`. Password, OIDC and GitHub logins store it in a server-side session (`session.Store`; the cookie holds a random ID only). One `session.Guard` puts the stored identity into the request context or refuses the request: `RequireAPI` answers 401 JSON, `RequireUI` 302 to the login. API keys and JWTs put an identity into the context without a session. Handlers read it with `auth.IdentityFrom(ctx)`. Authorization is an `authorization.Check`, a `func(context.Context) error` over that identity.

Core packages never log and never start goroutines; they report outcomes to an optional `auth.Observer`. Constructors are `New(options *Options) (*X, error)`: they validate the options, copy what they keep, never write to your struct and fail at startup.

## Packages

| Import `github.com/govengers/auth/...` | Use it for | Page |
|---|---|---|
| (root) `auth` | `Identity`, `Permission`, `IdentityFrom`, `Error` + `WriteError` + `ResponseFor`, `Observer`, `Hook`, `Route`, `RegisterRoutes`, `IdentityHandler` | [Errors-and-Observability](Errors-and-Observability.md), [Authorization](Authorization.md) |
| `session` | `Store` (cookie + server-side values), `Guard` (`RequireAPI`, `RequireUI`), `MemoryBackend`, `Refresher` | [Sessions](Sessions.md) |
| `session/redisbackend` | session backend shared by replicas | [Sessions](Sessions.md) |
| `password` | username/email + password login, TOTP, registration; you implement `Storage` | [Password](Password.md) |
| `oidc` | OIDC code flow login (Keycloak, Google, any IdP) and logout | [OIDC](OIDC.md) |
| `oidc/keycloak` | roles, groups and attributes from the Keycloak Admin API as an `OnLogin` hook | [OIDC](OIDC.md#keycloak-enrichment) |
| `github` | GitHub OAuth login, access by team, GitHub API calls as the user | [GitHub](GitHub.md) |
| `apikey` | static or application-issued API keys | [API-Keys](API-Keys.md) |
| `jwt` | sign identities (forward auth) and verify them in a backend | [JWT](JWT.md) |
| `authorization` | `Check` primitives and `All`, `Any`, `Not`, `Real` | [Authorization](Authorization.md) |
| `ginadapter` | net/http middleware and provider routes on gin, `Require`, wide-event `Observe` and `RedactQuery` | [Gin](Gin.md) |
| `prometheusadapter` | `Observer` counting outcomes on your registry | [Gin](Gin.md#prometheus) |
| `cmd/forwardauth` | the image `ghcr.io/govengers/forwardauth` for apps you do not change | [Forward-Auth](Forward-Auth.md) |

Importing one provider compiles none of the others' dependencies. Heavy dependencies per package: `session/redisbackend` go-redis, `password` x/crypto and otp, `oidc` go-oidc, `jwt` jwx v3, `ginadapter` gin and go-wide-event-logger, `prometheusadapter` client_golang.

## Which package for which need

- Users and password hashes live in your database: `password` + `session`. Example: [examples/password](../../examples/password/main.go).
- Users log in at Keycloak, Google or another OIDC IdP: `oidc` + `session`; add `oidc/keycloak` for composite roles and groups from the Admin API. Example: [examples/oidc](../../examples/oidc/main.go).
- Users log in with GitHub, access by team: `github` + `session`. Example on gin: [examples/github](../../examples/github/main.go).
- Machines call your API: `apikey` in front of the Guard.
- Your service sits behind the forward-auth image (or any `jwt.Signer`): `jwt.Verifier`, no sessions.
- You cannot change the app, or it is not Go: the [forward-auth image](Forward-Auth.md).
- More than one replica: `session/redisbackend`.
- Several login methods at once: one `Store` and one `Guard`, every provider on that store; an OIDC provider per IdP with distinct `Name`s.

## Wiring order (session-based providers)

1. Backend: `session.NewMemoryBackend(nil)` (one replica) or `redisbackend.New`.
2. `session.NewStore` with a 32-byte `EncryptionKey` (`session.ParseKey`).
3. Provider `New` with `Sessions: store`.
4. `session.NewGuard` with `LoginURL: provider.LoginURL()` and the provider in `Refreshers` (password, GitHub).
5. `auth.RegisterRoutes(serveMux, provider.Routes())` or `ginadapter.RegisterRoutes(engine, ...)`; provider routes are never behind the Guard.
6. `guard.RequireAPI()` / `RequireUI()` around your routes, authorization checks after the Guard.

## Pages

- [Password](Password.md): password login, `Storage`, TOTP, registration.
- [OIDC](OIDC.md): OIDC login and logout, Keycloak enrichment, Google.
- [GitHub](GitHub.md): GitHub login, teams, refresh, API client.
- [Sessions](Sessions.md): `Store`, `Guard`, backends, refresh, cookies.
- [Authorization](Authorization.md): identity fields, roles, permissions, checks, own checks.
- [JWT](JWT.md): `Signer`, `Verifier`, backend verification.
- [API-Keys](API-Keys.md): static keys and `Resolver`.
- [Gin](Gin.md): `ginadapter`, `prometheusadapter`.
- [Errors-and-Observability](Errors-and-Observability.md): `auth.Error`, status mapping, `Observer`, wide events.
- [Forward-Auth](Forward-Auth.md): the image and its Traefik wiring.
- [Forward-Auth-Configuration](Forward-Auth-Configuration.md): compose, TLS and Kubernetes wiring, routes, environment variables, operations.
- [Security](Security.md): guarantees and known limits.
- [Gotchas](Gotchas.md): the rules that are easy to get wrong.

Reference: [README](../../README.md) (overview), [design](../design.md) (binding design, flows, decisions), [migration](../migration.md) (from go-basicauth, oidc-fwd-auth, github-fwd-auth), [pkg.go.dev](https://pkg.go.dev/github.com/govengers/auth).
