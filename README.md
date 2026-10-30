# auth

[![CI](https://github.com/govengers/auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![unit tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/unit-tests.json)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![e2e tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/e2e-tests.json)](test/e2e)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/coverage.json)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/govengers/auth.svg)](https://pkg.go.dev/github.com/govengers/auth)
[![License](https://img.shields.io/github/license/govengers/auth)](LICENSE)

Coding agents: start at [llms.txt](llms.txt) and [docs/wiki/Home.md](docs/wiki/Home.md); runnable servers are in [examples/](examples/).

## What it is

One Go library for login and access control: password, OIDC (incl. Keycloak) and GitHub login, server-side sessions, authorization checks, JWT and API keys, plus a forward-auth image for Traefik. Every provider produces the same `auth.Identity` in the request context; for password, OIDC and GitHub logins one `session.Guard` puts it there from a server-side session. It replaces `mxcd/go-basicauth`, `mxcd/oidc-fwd-auth` and `mxcd/github-fwd-auth` ([migration guide](docs/migration.md)).

## Features

- Password login with Argon2id, TOTP with backup codes, optional registration, bcrypt upgrade; users stay in your database.
- OIDC code flow with PKCE and nonce, RP-initiated and front-channel logout, Keycloak Admin API enrichment, Google.
- GitHub OAuth with allowed, admin and relevant teams, re-checked every minute.
- Server-side sessions (memory or Redis), the cookie holds a random ID only.
- Authorization checks over roles, groups, teams and resource permissions (`builds:write`), composable with `All`, `Any`, `Not`.
- API keys, RS512 JWT signing and verification.
- `net/http` core; gin, wide events and Prometheus in adapter packages. No logging, no goroutines.

## Install

```bash
go get github.com/govengers/auth@v1
```

## Quick start

Provider, Guard and routes, from [examples/password/main.go](examples/password/main.go):

```go
	provider, err := password.New(&password.Options{
		Sessions:           store,
		Storage:            options.Storage,
		EnableRegistration: true,                                                   // POST /auth/password/register
		TOTP:               password.TOTPOptions{Enabled: true, Issuer: "Example"}, // optional second factor
		OnLogin:            grantRoles(options.AdministratorID),
	})
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{
		Store:      store,
		LoginURL:   "/login",                      // where RequireUI sends anonymous browsers
		Refreshers: []session.Refresher{provider}, // a deleted user loses access within a minute
	})
	if err != nil {
		return nil, err
	}

	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes()) // the provider reads the session itself: no Guard in front
	serveMux.Handle("GET /auth/me", guard.RequireAPI()(auth.IdentityHandler()))
	serveMux.Handle("GET /api/notes", guard.RequireAPI()(http.HandlerFunc(listNotes)))
	serveMux.Handle("DELETE /api/notes", guard.RequireAPI()(authorize(authorization.IsAdmin())(http.HandlerFunc(deleteNotes))))
	serveMux.Handle("GET /{$}", guard.RequireUI()(http.HandlerFunc(home)))
```

Complete, tested servers: [password](examples/password/main.go), [OIDC with Keycloak](examples/oidc/main.go), [GitHub on gin](examples/github/main.go).

## Packages

| Package | Purpose |
|---|---|
| [`auth`](docs/wiki/Errors-and-Observability.md) | `Identity`, `Permission`, context helpers, `Error` and the JSON error shape, `Observer`, `Hook`, `Route` |
| [`session`](docs/wiki/Sessions.md) | server-side sessions: `Store`, `Guard` (`RequireAPI`, `RequireUI`), memory backend, refresh |
| [`session/redisbackend`](docs/wiki/Sessions.md#backends) | session backend on Redis, shared by replicas |
| [`password`](docs/wiki/Password.md) | password login, TOTP, registration; you implement `Storage` |
| [`oidc`](docs/wiki/OIDC.md) | OIDC login and logout |
| [`oidc/keycloak`](docs/wiki/OIDC.md#keycloak-enrichment) | Keycloak Admin API enrichment as an `OnLogin` hook |
| [`github`](docs/wiki/GitHub.md) | GitHub OAuth with teams and an API client for the user |
| [`apikey`](docs/wiki/API-Keys.md) | static and application-issued API keys |
| [`jwt`](docs/wiki/JWT.md) | RS512 `Signer` with JWKS, `Verifier` with middleware |
| [`authorization`](docs/wiki/Authorization.md) | `Check` primitives and combinators |
| [`ginadapter`](docs/wiki/Gin.md) | net/http middleware and routes on gin, `Require`, wide-event `Observe`, `RedactQuery` |
| [`prometheusadapter`](docs/wiki/Gin.md#prometheus) | outcome counter on your Prometheus registry |
| [`cmd/forwardauth`](docs/wiki/Forward-Auth.md) | the forward-auth binary |

## Forward-auth image

`ghcr.io/govengers/forwardauth` runs one OIDC or GitHub provider in front of any app behind Traefik, without code in the app. It answers Traefik's forwardAuth checks and can pass the identity on as a signed JWT, which Go backends verify with `jwt.Verifier`. Overview: [docs/wiki/Forward-Auth.md](docs/wiki/Forward-Auth.md); compose, TLS and Kubernetes wiring and every environment variable: [docs/wiki/Forward-Auth-Configuration.md](docs/wiki/Forward-Auth-Configuration.md).

## Documentation

- [docs/wiki/Home.md](docs/wiki/Home.md): guides per provider and topic, gotchas.
- [llms.txt](llms.txt): index for coding agents.
- [docs/design.md](docs/design.md): binding design, flows and decision log.
- [docs/migration.md](docs/migration.md): migration from go-basicauth, oidc-fwd-auth and github-fwd-auth.
- [pkg.go.dev](https://pkg.go.dev/github.com/govengers/auth): API reference.

Releases and changelog: [GitHub Releases](https://github.com/govengers/auth/releases).

## Security

Guarantees and known limits (no rate limiting, among others): [docs/wiki/Security.md](docs/wiki/Security.md).

## Contributing

`just check` runs lint, unit tests with `-race` and an 80 % coverage gate (total and per package), both end-to-end suites and `govulncheck`; `just docker-build` builds the image. Code follows the [govengers standards](https://github.com/govengers/standards) with the `library` profile (`.govengers.yml`; one waived rule, DES-008, reason in the file); reviewers also apply the service rules (CFG, LAY, LOG, MET, DEP, API-001, API-002) to `cmd/forwardauth` and `internal/forwardauth`. CI, image and e2e details: [docs/infrastructure-notes.md](docs/infrastructure-notes.md). Releases: push a `vX.Y.Z` tag; the release workflow publishes the image. After the very first push the GHCR package must be made public once by hand (package settings; there is no API for it).

## License

[Apache 2.0](LICENSE)
