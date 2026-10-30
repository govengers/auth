# Gotchas

The rules agents and humans get wrong most often, one line each with the page that explains it.

## Wiring

- Provider routes are never behind the Guard; register them with `auth.RegisterRoutes` / `ginadapter.RegisterRoutes` on the root. [Home](Home.md#wiring-order-session-based-providers)
- Put the password and GitHub providers into `GuardOptions.Refreshers`, or deleted users and removed team members keep access until `MaximumAge`. [Sessions](Sessions.md#refresh)
- `apikey` middleware goes before the Guard, never in front of a `jwt.Verifier` (both read `Authorization: Bearer`). [API-Keys](API-Keys.md#gotchas)
- net/http has no built-in check middleware; wrap the check yourself (`authorize` in the examples) or use `ginadapter.Require`. [Authorization](Authorization.md#mounting-a-check)
- `internal/fakeprovider` and `internal/backendtest` are not importable outside this module; write your own fakes for consumer tests.
- The wide-event middleware logs `request.query` verbatim, OAuth callbacks included (`code`, `state`); mount it with `wideevent.WithPreEnricher(ginadapter.RedactQuery)`. [Gin](Gin.md#wide-events)

## Identity and hooks

- `OnLogin` must not mutate its argument: return `identity.Clone()` with changes. [Authorization](Authorization.md#roles-from-your-application)
- The password provider's `OnLogin` must keep `UserID`, or the login fails with 500. [Password](Password.md#gotchas)
- `UserID` is `uuid.Nil` for OIDC, GitHub and API keys until your `OnLogin` (or `Resolver`) sets it; `HasUserID` never matches `uuid.Nil`. [Authorization](Authorization.md#identity-fields-and-who-fills-them)
- Inactive identities (`Active: false`), and identities impersonated by an inactive one, pass only `IsAuthenticated`; a `Resolver` must set `Active: true`. [API-Keys](API-Keys.md#behaviour)
- Impersonate only through `session.Impersonator`: `SaveIdentity` and `SwapIdentity` refuse an identity or impersonator of another provider or subject than the session holds, and a stored impersonation without the Impersonator's end time ends at the next request. [Sessions](Sessions.md#impersonation)
- Roles from `OnLogin` and OIDC roles are fixed for the session's lifetime; only the password (user deleted, password or second factor changed) and GitHub (teams) refreshers change a running session. [Sessions](Sessions.md#refresh)
- The GitHub refresher re-derives `auth.RoleAdmin` from `AdminTeams` on every refresh, so an `OnLogin` that strips `admin` is undone; gate on a role of your own instead. [GitHub](GitHub.md#identity)
- Browser sessions carry no `Permissions` unless a hook grants them; `HasPermission` alone locks interactive users out. [Authorization](Authorization.md#permissions)

## Redirects and cookies

- Logout (all providers) and GitHub refresh-teams refuse `Sec-Fetch-Site: cross-site` with 403: put logout links on the app's own site. [OIDC](OIDC.md#gotchas)
- `return_to` is accepted only as a same-origin path (`/...`, not `//` or `/\`, at most 2048 bytes); anything else becomes `/`. [Security](Security.md#guarantees)
- `LoginURL`, `ErrorURL` and `PostLogoutURL` are validated at startup and refuse fragments. [OIDC](OIDC.md#options-that-matter)
- The cookie is named `__Host-<CookieName>` while it is Secure, host-only and on `/`; look for `__Host-auth_session`, not `auth_session`. [Sessions](Sessions.md#store)
- Plain `http` off loopback loops every login unless `InsecureCookie` (`SESSION_INSECURE_COOKIE`) is set; local development only. [Sessions](Sessions.md#gotchas)
- Front-channel logout needs `SameSite: None`; `oidc.New` and `github.New` refuse a `Strict` store (the callback would arrive without the cookie). [Sessions](Sessions.md#gotchas)
- No component follows redirects of IdP, token, JWKS, Keycloak or GitHub endpoints (`redirect refused`); configure the final URLs. [OIDC](OIDC.md#gotchas)
- Issuer, discovered endpoints, Keycloak and GitHub URLs must be `https`; `http` only on loopback hosts. [OIDC](OIDC.md#options-that-matter)

## Known limits

- No rate limiting: rate-limit the password login, `POST {prefix}/register` (an anonymous Argon2id, like login) and TOTP routes at the edge. [Password](Password.md#gotchas)
- No retries, no idle timeout, no key rotation list; changing `EncryptionKey` logs everyone out. [Sessions](Sessions.md#store)
- `MemoryBackend` is for one replica at non-production scale; use `redisbackend` in production. [Sessions](Sessions.md#backends)
- A stale `SaveIdentity` from your code can race a Guard refresh; use `Session.SwapIdentity`. [Sessions](Sessions.md#store)
- Google needs an admission (`AllowedEmailDomains`, `OnLogin` or `AllowAnyAccount`), else `oidc.New` refuses; an allowed Workspace domain also requires `hd`, so a consumer Google account with a company address is 403. [OIDC](OIDC.md#gotchas)
- Full list: [Security](Security.md).
