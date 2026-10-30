# Forward auth

The image `ghcr.io/govengers/forwardauth` (binary `cmd/forwardauth`) runs one provider, `PROVIDER=oidc` (optionally with Keycloak enrichment) or `PROVIDER=github`, in front of any app behind Traefik. It needs no code in the app; a Go backend verifies the optional JWT with [`jwt.Verifier`](JWT.md). Password login is not offered.

## What it does

- Traefik's `forwardAuth` middleware calls `GET {prefix}/ui` (browsers: 302 to the login when unauthenticated) or `GET {prefix}/api` (APIs: 401 JSON) for every request.
- 200 lets the request through, with a signed JWT in `Authorization` (`JWT_ENABLED=true`); 302, 401 and 403 go to the client.
- Login, callback, logout and the JWKS are served under `{prefix}` (default `/auth`) on the app's own host, through a separate Traefik router.
- Optional static API keys (`API_KEYS_ENABLED`) with permissions, no roles.
- One instance serves one external origin; without Redis (`SESSION_REDIS_ENABLED`) it is a single replica.

## Routes

`{prefix}/ui`, `{prefix}/api` (checks), `{prefix}/jwks`, `{prefix}/me` (optional), `{prefix}/health`, `{prefix}/ready`, the provider routes (`{prefix}/oidc/<OIDC_NAME>/...` or `{prefix}/github/...`) and `GET /metrics` on `METRICS_PORT`. Table with answers: [Forward-Auth-Configuration](Forward-Auth-Configuration.md#routes).

## Configuration

Environment variables only; the process lists every problem and exits before serving. Full table with defaults: [Forward-Auth-Configuration](Forward-Auth-Configuration.md#environment-variables). The minimum: `PROVIDER`, `EXTERNAL_URL` (origin without path), `SESSION_ENCRYPTION_KEY`, plus `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` or `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_ALLOWED_TEAMS`. Callback URL to register: `<EXTERNAL_URL><PATH_PREFIX>/oidc/<OIDC_NAME>/callback` or `<EXTERNAL_URL><PATH_PREFIX>/github/callback`.

## Traefik wiring

Copy from [Forward-Auth-Configuration](Forward-Auth-Configuration.md#quick-start-docker-compose) (docker labels, production with TLS, Kubernetes CRDs); the tested stack is [test/e2e/compose](../../test/e2e/compose/compose.yml). The rules that matter:

- A router for `PathPrefix(/auth)` to forwardauth without the forwardAuth middleware, excluding `/auth/ui`, `/auth/api`, `/auth/health` and `/auth/ready` (one `!Path` each); the checks and probes stay internal.
- forwardAuth middleware: `authResponseHeaders` `Authorization` and `X-API-Key` (Traefik strips the client's copies; a forged token never reaches the app), `trustForwardHeader: false`, `maxResponseBodySize`.
- Entrypoints: `http.aliasHeadersStrategy=delete`.
- Probes at `{prefix}/health` and `{prefix}/ready` on port 8080; keep `METRICS_PORT` off Traefik.

## Gotchas

- `EXTERNAL_URL` on plain `http` off loopback needs `SESSION_INSECURE_COOKIE=true` (local only); `app.localhost` is not loopback.
- `JWT_PRIVATE_KEY` is required with `JWT_ENABLED`; no generated key, so every replica signs with the same one.
- With `API_KEYS_ENABLED`, a bearer token that is not a configured key is 401 on both checks, even with a session cookie.
- An inactive identity is 403 on both checks.
- Logout links (`{prefix}/oidc/<name>/logout`, `{prefix}/github/logout`) must be on the app's own site.

Source: [cmd/forwardauth/main.go](../../cmd/forwardauth/main.go), [internal/forwardauth/](../../internal/forwardauth/), [docs/infrastructure-notes.md](../infrastructure-notes.md) (image, CI, e2e).
