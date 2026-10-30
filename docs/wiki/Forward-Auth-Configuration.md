# Forward-auth configuration

Deployment reference of the forward-auth image `ghcr.io/govengers/forwardauth`: Traefik wiring (docker compose, production, Kubernetes), routes, every environment variable, the JWT it signs and operations. Overview: [Forward-Auth](Forward-Auth.md).

## Image

`ghcr.io/govengers/forwardauth` (about 22 MB, distroless `static-debian13`, non-root, `linux/amd64` and `linux/arm64`, ports 8080 and 9090) runs one provider, `PROVIDER=oidc` or `PROVIDER=github`, in front of any app behind Traefik. Tags: `:1.0.0`, `:1.0`, `:1` and `:latest` per release, `:main` from the main branch. Traefik calls `GET /auth/ui` (browsers) or `GET /auth/api` (APIs) for each request. 200 lets the request through, with a signed JWT in `Authorization` when `JWT_ENABLED`; anything else (302 to the login, 401, 403) goes to the client. Password login is not offered (Traefik's `basicAuth` covers static users). One instance serves one external origin. Without Redis it is a single replica.

## Quick start (docker compose)

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

## Production with TLS

Production: `EXTERNAL_URL: https://app.example.com` without `SESSION_INSECURE_COOKIE`, the routers on ``Host(`app.example.com`)``, and a TLS entrypoint in Traefik: `--entrypoints.websecure.address=:443`, `--entrypoints.websecure.http.tls.certresolver=<your resolver>`, `--entrypoints.websecure.http.aliasHeadersStrategy=delete` and `--entrypoints.web.http.redirections.entrypoint.to=websecure`, with port 443 published. Register the `https://` callback URL.

## Traefik settings

Traefik settings that matter (verified on Traefik v3.7):

- `authResponseHeaders: [Authorization, X-API-Key]`: Traefik deletes the client's `Authorization` and `X-API-Key` headers and puts the JWT in place of the first; with JWT disabled both are simply gone. A forged token never reaches the app, and neither does a raw API key: both headers reach forwardauth only, where they are the API key credential. A different `JWT_HEADER` goes into the list as well.
- `trustForwardHeader: false`: client-sent `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Forwarded-Uri` never reach forwardauth, so they cannot steer the return path. Set it `true` only behind another trusted proxy.
- `aliasHeadersStrategy: delete` on the entrypoints: headers like `X_Auth_User` cannot alias a header the auth response sets.
- `maxResponseBodySize` bounds what Traefik reads from forwardauth.
- forwardauth answers redirects with absolute URLs; Traefik resolves a relative `Location` against the forwardAuth address (`http://forwardauth:8080/...`).

## Kubernetes

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

## Routes

`{prefix}` is `PATH_PREFIX` (default `/auth`).

| Route | Purpose |
|---|---|
| `GET {prefix}/ui` | forward-auth check for browsers: 302 to the login when unauthenticated |
| `GET {prefix}/api` | forward-auth check for APIs: 401 JSON when unauthenticated |
| `GET {prefix}/jwks` | public keys of the JWT signer (`JWT_ENABLED`), `Cache-Control: public, max-age=300` |
| `GET {prefix}/me` | the caller's identity as JSON (`IDENTITY_ENDPOINT_ENABLED`; sessions only, not API keys); an inactive identity gets 403 like on the checks |
| `GET {prefix}/health` | liveness, 200 `{"status":"ok"}` |
| `GET {prefix}/ready` | readiness: 200 `{"status":"ok"}`, or 503 `{"code":"unavailable","message":"not ready"}` during shutdown or when the Redis ping (2 s) fails; a failed ping is kept as a wide event, successful probes are sampled |
| `GET {prefix}/oidc/<OIDC_NAME>/{login,callback,logout,frontchannel-logout}` | OIDC provider |
| `GET {prefix}/github/{login,callback,logout}`, `POST {prefix}/github/refresh-teams` | GitHub provider |
| any other path | 404 `{"code":"not_found","message":"not found"}`, also a known route with a trailing `/` (no redirect) or with a percent-encoded character (`{prefix}/%75i`): routes match the path as sent, not the decoded one |
| `GET /metrics` on `METRICS_PORT` | Prometheus, the only route of that listener; keep this port off Traefik |

Route `{prefix}` to the service with its own Traefik router, minus the checks and probes, as in the labels above: the check endpoints do not dispatch login routes by `X-Forwarded-Uri`. Link users to `{prefix}/oidc/<name>/logout` or `{prefix}/github/logout` to log out; both are plain `GET` links, same-site only: a link from another site (`Sec-Fetch-Site: cross-site`, e.g. a portal on another domain) is refused with 403.

## Environment variables

Values without a default are required. *not empty* marks values with a default that refuse an explicitly empty value. Lists are comma-separated. The process exits non-zero before it serves anything and lists every problem it can find: missing or invalid values, an `EXTERNAL_URL` with a path, a plain `http` `EXTERNAL_URL` off loopback without `SESSION_INSECURE_COOKIE=true` (browsers would drop the `Secure` cookie and loop every login), an unparsable `SESSION_ENCRYPTION_KEY`, `PORT` equal to `METRICS_PORT`, values the selected provider, Keycloak or JWT needs, `KEYCLOAK_ENABLED` without `PROVIDER=oidc`, `API_KEYS_ENABLED` without keys, a malformed `API_KEYS` entry (reported by position, never echoed), a secret that is too short or used twice, a bad `API_KEY_PERMISSIONS` entry. Then the components fail the boot on what only they can judge (team format, `GITHUB_SCOPES`, URLs, the JWT key, the issuer's discovery) and, with `SESSION_REDIS_ENABLED`, on a Redis that does not answer a `PING` within 5 s. Sensitive values are masked in the startup table. A `.env` file in the working directory is read if present (development only; the image has none).

### General

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

### Session

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `SESSION_ENCRYPTION_KEY` | - | yes | yes | base64 of 32 bytes: `openssl rand -base64 32` |
| `SESSION_COOKIE_NAME` | `forwardauth_session` | not empty | | sent as `__Host-forwardauth_session` unless `SESSION_COOKIE_DOMAIN` or `SESSION_INSECURE_COOKIE` is set (a `__Host-` or `__Secure-` name of your own is kept and must fit its prefix) |
| `SESSION_COOKIE_DOMAIN` | empty | | | empty is a host-only cookie |
| `SESSION_INSECURE_COOKIE` | `false` | | | drops `Secure`; local HTTP development only; required for an `http` `EXTERNAL_URL` whose host is not loopback (`app.localhost` is not); refused with an `https` `EXTERNAL_URL` |
| `SESSION_SAME_SITE` | `lax` | not empty | | `lax` or `none` (`none` for front-channel logout; not with an insecure cookie). `strict` is refused: the browser would withhold the cookie, and the login state with it, on the redirect back from the provider |
| `SESSION_MAXIMUM_AGE_SECONDS` | `86400` | | | absolute lifetime, at least 1; refreshes never extend it |
| `SESSION_REFRESH_INTERVAL_SECONDS` | `60` | | | how often the GitHub provider re-checks teams; at least 1 |
| `SESSION_MAXIMUM_UNVERIFIED_AGE_SECONDS` | `3600` | | | a team re-check failing (GitHub outage, rate limit) for longer than this since the last successful one ends the session; at least `SESSION_REFRESH_INTERVAL_SECONDS` |
| `SESSION_REDIS_ENABLED` | `false` | | | otherwise in-memory: exactly one replica, not built for anonymous login floods (each start stores a session; a full backend evicts the soonest expiring): rate-limit `{prefix}/login` or use Redis |
| `SESSION_REDIS_ADDRESS` | empty | with Redis | | `host:port`; pinged at boot (5 s) |
| `SESSION_REDIS_PASSWORD` | empty | | yes | |
| `SESSION_REDIS_DATABASE` | `0` | | | at least 0 |
| `SESSION_REDIS_KEY_PREFIX` | `forwardauth` | not empty | | |

### OIDC (`PROVIDER=oidc`)

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

### Keycloak (optional, with `PROVIDER=oidc`)

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `KEYCLOAK_ENABLED` | `false` | | | enrich identities through the Admin API; needs `PROVIDER=oidc` |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM` | empty | when enabled | | |
| `KEYCLOAK_AUTHENTICATION_REALM` | empty | | | realm the service account logs into (e.g. `master`); empty means `KEYCLOAK_REALM` |
| `KEYCLOAK_GRANT_TYPE` | `client_credentials` | not empty | | or `password` |
| `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | empty | client credentials | secret | |
| `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD` | empty | password grant | password | |
| `KEYCLOAK_CLIENT_ROLES_CLIENT_ID` | empty | | | client whose roles become client roles |
| `KEYCLOAK_REQUIRED_REALM_ROLES`, `KEYCLOAK_REQUIRED_CLIENT_ROLES`, `KEYCLOAK_REQUIRED_GROUPS` | empty | | | login is refused (403) when one is missing; groups are paths; required client roles need `KEYCLOAK_CLIENT_ROLES_CLIENT_ID`; refused without `KEYCLOAK_ENABLED=true` |

### GitHub (`PROVIDER=github`)

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

### JWT

| Variable | Default | Required | Sensitive | Notes |
|---|---|---|---|---|
| `JWT_ENABLED` | `false` | | | sign an identity token per allowed request |
| `JWT_PRIVATE_KEY` | empty | when enabled | yes | PEM RSA key, at least 2048 bits; no generated fallback, so every replica signs with the same key |
| `JWT_ISSUER` | empty | | | what backends configure as `Issuer`; empty means `EXTERNAL_URL` |
| `JWT_AUDIENCE` | empty | | | |
| `JWT_LIFETIME_SECONDS` | `300` | | | 1 to 86400 |
| `JWT_HEADER` | `Authorization` | not empty | | value `Bearer <jwt>`; list the header in `authResponseHeaders`; a header name, not `Cache-Control`, `Set-Cookie`, `Connection`, `Content-Length`, `Transfer-Encoding`, `Cookie` or `Host` |

The token carries `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `provider`, `user_id`, `preferred_username`, `name`, `email`, `picture`, `roles`, `realm_roles`, `client_roles`, `groups`, `teams`, `permissions` (empty ones omitted) and every other claim of the OIDC ID token; ID token claims with these names (and `nonce`, `at_hash`, `c_hash`, `auth_time`, `sid`, `azp`, and Keycloak's raw `realm_access` and `resource_access`, which the token carries as `realm_roles` and `client_roles`) are never copied, in any letter case, so an IdP `roles` or `Roles` claim cannot become application roles. For GitHub, `sub` is the numeric user ID and the login is `preferred_username`. Verify it in your backend as shown in [JWT](JWT.md).

## Operations

- Logs are wide events: one JSON line per request on stdout, none for health. Readiness requests are sampled like any other (`WIDE_EVENT_SAMPLE_RATE`); a failed readiness check is always kept with its cause. Query values are redacted (callbacks carry `code` and `state`), also by the `DEV_MODE` emitter; every field a client controls (method, path, query names, host, user agent, request ID, the `X-Forwarded-*` values) is cut to 512 bytes, and request line plus headers are limited to 64 KiB (431 above). Each event sums the request's outbound calls per dependency: `cache.calls`, `.failures`, `.duration_ms`, `.error` for Redis and `http.<oidc|keycloak|github>.calls`, `.failures`, `.duration_ms`, `.status`, `.error` for the provider (a transport error is recorded as cancellation, a dial error or its type, never with the URL or bytes the server sent). Unknown paths are recorded as failures (`no route`) and always kept by the sampler. Startup, shutdown and net/http's own error lines go through `log/slog` JSON.
- Metrics on `METRICS_PORT`: `forwardauth_http_requests_total{route,method,status}`, `forwardauth_http_request_duration_seconds{route,method}`, `forwardauth_http_requests_in_flight`, `forwardauth_auth_outcomes_total{provider,action,result}`, `forwardauth_dependency_request_duration_seconds{dependency,operation,outcome}` (Redis and the provider's HTTP calls), Go, process and build-info collectors.
- With `SESSION_REDIS_ENABLED` the boot fails when Redis does not answer within 5 s; the Redis client never retries a command.
- With `API_KEYS_ENABLED=true` the keys in `API_KEYS` are accepted on both check endpoints (not on `{prefix}/me`). Their identity carries the permissions from `API_KEY_PERMISSIONS` and no roles, so `authorization.IsAdmin` refuses them: check permissions in the backend (`HasPermission`, `RequireMethodPermission`). With API keys enabled, a request whose `Authorization: Bearer` value is not a configured key is refused with 401 `invalid_api_key` on both checks, even with a valid session cookie: an SPA that sends its own bearer tokens through the proxy cannot use API keys.
- An inactive identity is answered 403 `forbidden` on both checks, with or without `JWT_ENABLED` (a token would come back active).
- Failures answer the one JSON shape (a panic is 500 `internal`); check answers carry `Cache-Control: no-store`.
- Both listeners bound every connection phase (read header 10 s, read 30 s, write 60 s, idle 120 s).
