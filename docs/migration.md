# Migrating to govengers/auth v1

`github.com/govengers/auth` v1.0.0 replaces three modules and two images:

| Old | New |
|---|---|
| `github.com/mxcd/go-basicauth` v1.5.x | `password` + `session` (+ `ginadapter`, `authorization`) |
| `github.com/mxcd/oidc-fwd-auth/pkg/{oidc,jwt}` v0.9.x | `oidc`, `oidc/keycloak`, `session`, `jwt` |
| `github.com/mxcd/github-fwd-auth/pkg/githuboauth` v1.4.x | `github`, `apikey`, `session`, `jwt` |
| images `oidc-fwd-auth`, `github-fwd-auth` | one image `ghcr.io/govengers/forwardauth`, `PROVIDER=oidc` or `github` |

There are no compatibility shims, and the old modules are not touched. Sections 1 to 3 cover the libraries, section 4 the images. Read "Changes for every library" first.

## Changes for every library

| Topic | Before | Now |
|---|---|---|
| Sessions | cookie-held data (basicauth, github) or a server-side session behind a signed cookie (oidc) | server-side for every provider (`session.Store` + `Backend`); the cookie holds 32 random bytes. **Existing sessions are invalid: every user logs in once.** Redis keys of the old libraries are ignored; use a new `KeyPrefix` and delete the old keys. An own backend implements the five methods of `session.Backend`, `CompareAndSwap` included |
| Keys | signing key (64 bytes) + encryption key (32 bytes) | one `EncryptionKey` of exactly 32 bytes, base64 via `openssl rand -base64 32`, parsed by `session.ParseKey`. Same value on every replica. No key rotation list |
| Cookie defaults | names `basicauth_session`, `oidc_fwd_auth_session`, `session_id`; domain `localhost` in the binaries | name `auth_session` (library) or `forwardauth_session` (image), sent as `__Host-auth_session` / `__Host-forwardauth_session` while the cookie is Secure, host-only and on path `/` (the default; users log in once after upgrading from an earlier version of this module); host-only unless `CookieDomain` is set; always `HttpOnly`; `Secure` unless `InsecureCookie`; `SameSite=Lax` |
| Session lifetime | 24 h (basicauth, oidc), 7 days (github binary) | `MaximumAge`, default 24 h, absolute from the first login, never extended |
| Middleware | per provider, often global (`Engine.Use`), `PathRules`, `PublicPaths` | one `session.Guard`: `RequireAPI()` (401 JSON) or `RequireUI()` (302 to login) mounted on the route groups you want protected. Provider routes are never behind the Guard |
| Identity | `basicauth.User`, `oidc.SessionData`, `jwt.User`, GitHub session user, gin keys | `auth.Identity` in the request context: `auth.IdentityFrom(ctx)`; gin: `auth.IdentityFrom(c.Request.Context())` |
| Authorization | `Handle.IsAdmin`, ad-hoc role checks, access levels in API key data | `authorization.Check`s; gin: `ginadapter.Require(check)`; resource permissions `<resource>:<access>` (`auth.Permission`, `authorization.HasPermission`, `ginadapter.RequireMethodPermission`, JWT `permissions` claim); no permission means no access |
| Errors | `{"error","message"}` and other shapes, translated messages | `{"code","message"}`, fixed messages, stable codes; `errors.Is` against `auth.ErrUnauthenticated`, `ErrForbidden`, `ErrInvalidRequest`, `ErrConflict` |
| Hooks | `PostLoginHook(c, *SessionData) error`, `PostLogoutHook(c)`, `UserTransformer` | `OnLogin auth.Hook` (return a changed copy, or an `*auth.Error` to refuse), `OnLogout auth.LogoutHook`; `UserTransformer` becomes a middleware after the Guard |
| Logging | the libraries logged themselves (zerolog) | libraries never log; pass an `auth.Observer` (`ginadapter.Observe`, `prometheusadapter`) |
| Redirect providers | GitHub logout `POST`; free-form paths and redirect targets | OIDC and GitHub logout is `GET`; every logout (password included) refuses a request the browser marks `Sec-Fetch-Site: cross-site` with 403 `forbidden`, so logout links must live on the app's own site; the return path (`return_to`) accepts same-origin relative paths only; `ErrorURL` and `PostLogoutURL` take a path or an absolute `http(s)` URL without fragment and are made absolute with `ExternalURL` |
| Path prefixes | free-form base paths (`AuthenticationBaseUrl`, `AuthBaseContextPath`, `LoginPath`, ...) | `PathPrefix` of password, OIDC and GitHub: `/`-separated segments of `A-Z a-z 0-9 . _ ~ -`, no trailing `/`, no `.` or `..` segment |
| API keys | unnamed secrets (github) | `apikey`: named keys, secrets of 16 bytes or more, names and secrets unique, optional roles and permissions; keys you issue go through a `Resolver`; `Authorization: Bearer` matched in any case |
| Go | - | 1.26 |

Untouched on purpose: no rate limiting (put one at the edge, at least on the password login and TOTP routes), no retries.

## 1. go-basicauth (v1.5.x) to `password`

### Behaviour changes

- **Guard instead of global middleware.** `RegisterRoutes()` called `Engine.Use(RequireAuth())`, so everything was protected unless a path rule said otherwise. Now only groups behind `ginadapter.Middleware(guard.RequireAPI())` are protected.
- **Password policy.** Old defaults: minimum 8 characters with upper case, lower case and a digit. New default: minimum 12 characters (counted as runes, not bytes), no composition rules, maximum 128 bytes (was 72). Keep the old policy with `Policy{MinimumLength: 8, RequireUppercase: true, RequireLowercase: true, RequireDigit: true}`. The policy applies at registration.
- **Hashes.** The Argon2id format is unchanged (`$argon2id$v=19$m=..,t=..,p=..$salt$hash`); existing hashes verify. `LegacyVerifier: password.VerifyBcrypt` still upgrades foreign hashes, now only at login (not in the password checks of the TOTP routes) and with a compare-and-swap write; login also rehashes Argon2id hashes whose parameters differ from `HashParameters`. A stored hash that neither `Verify` nor the `LegacyVerifier` can read answers 401 `invalid_credentials`, like a wrong password and at the same cost. `HashParameters` must be at least 32 MiB, 1 iteration, salt and key 16 bytes.
- **TOTP.** Routes move from `/tfa/*` to `/totp/*` and exist only with `TOTP.Enabled` (otherwise 404); while it is off, users who enrolled cannot log in (500), so clear their TOTP in storage before switching it off. `Digits` is 6 or 8, `Period` at most 3600, `Skew` at most 10. `TFA.Required` no longer answers 403 `tfa_setup_required` on every route: login (and registration) answers 202 `{"challenge":"totp_setup"}` and the user enrolls through `/totp/setup` and `/totp/enable` before a full session exists. `AccountLabel` is gone (username, else email, else ID).
- **TOTP enable.** A wrong code can be retried with the same setup (the secret stays until the enrollment completes, TOTP is disabled or its 10 minutes pass). Of two concurrent enrollments only the first enables TOTP; the other gets 409 `totp_already_enabled` (`Storage.SetTOTP` decides, see the recipe).
- **TOTP codes are single use.** The storage records the last used time step (`ConsumeTOTPStep`); a code is accepted once, also across logins and at enable time. A user who re-enables TOTP within the 30 s step of their last used code gets that one code refused; the next works.
- **Attempts are a lockout.** `MaxVerifyAttempts: 0` meant unlimited; `MaximumAttempts: 0` now means the default 5, a negative value is an error, there is no unlimited mode. The password login no longer resets the counter (go-basicauth reset it at every login, so each login brought fresh guesses): wrong codes count across logins until a code is verified, `SetTOTP`, `ClearTOTP`, or your application calls `ResetTOTPAttempts` to unlock the user (an admin action). Whoever knows the password can lock the second factor; rate-limit `{prefix}/login` and `{prefix}/totp/verify` at the edge.
- **Backup codes.** The verify body's `isBackupCode` becomes `backupCode`, and the code is checked against the backup codes only with `"backupCode": true`; a wrong TOTP code no longer falls through to them, so a backup code typed into the TOTP field is a wrong code. Codes are drawn without duplicates; `BackupCodeCount` is at most 20, a code at most 128 bytes, and alphabet and length must give at least 1,000,000 distinct codes (6 decimal digits is the smallest); repeated alphabet characters count once.
- **Freshness.** The old handler re-read the user on every request. The Guard calls `Provider.Refresh` at most once per `RefreshInterval` (default 1 minute): a deleted user gets 401, so does a session opened before a password or TOTP change, a changed username or email is picked up. Sessions from before the credential stamp (D45) end at their first refresh. Pass the provider in `GuardOptions.Refreshers`.
- **Responses.** Login success is the `IdentityResponse` (`{"provider","subject","userId","username","email","active","roles",...}`) instead of `{"message","data":UserResponse}`; `id` is now `userId` (and `subject`); `createdAt`, `updatedAt`, `isTechnicalUser` and `totpEnabled` are gone (`GET /auth/password/totp` returns `{"enabled"}`). TOTP challenge is 202 `{"challenge":"totp"}` (was `{"data":{"tfaRequired":true}}`). Logout is 204, or 403 `forbidden` for a cross-site request (`Sec-Fetch-Site: cross-site`). Error body is `{"code","message"}`; `tfa_*` codes became `totp_*`, `unauthorized` became `unauthenticated`, `invalid_request` is unchanged. Client codes are in [docs/wiki/Errors-and-Observability.md](wiki/Errors-and-Observability.md#client-codes).
- **`/me`.** The provider no longer serves it. Mount `auth.IdentityHandler()` behind the Guard at a path you choose.
- **Storage.** See the recipe.
- **User context.** `UserKey` and `UserTransformer` are gone; the app-user middleware pattern is in [docs/wiki/Authorization.md](wiki/Authorization.md#your-application-user).

### Symbol map

| Old | New |
|---|---|
| `basicauth.NewHandler(&Options{Engine, AuthenticationBaseUrl, Storage, Settings, UserKey, UserTransformer})` | `session.NewStore`, `password.New(&password.Options{Sessions, Storage, PathPrefix, ...})`, `session.NewGuard` |
| `(*Handler).RegisterRoutes()` (global `Engine.Use`) | `ginadapter.RegisterRoutes(engine, provider.Routes())` + `group.Use(ginadapter.Middleware(guard.RequireAPI()))` |
| `RequireAuth()` | `guard.RequireAPI()` |
| `PathRules`, `PublicPaths` | mount the Guard only on protected groups |
| `GetUserFromContext(c)`, gin key `"user"` | `auth.IdentityFrom(ctx)` |
| `UserKey`, `UserTransformer` | app middleware after the Guard; provisioning in `OnLogin` |
| `BasicAuthSettings.EnableUsernameLogin` / `EnableEmailLogin` | `DisableUsernameLogin` / `DisableEmailLogin` (inverted) |
| `EnableTFA`, `TFA` | `TOTP.Enabled` (also routes the TOTP endpoints), `TOTP` (`MaxVerifyAttempts` is `MaximumAttempts`, 0 no longer unlimited, counted across logins; `SkewWindows` is `Skew`, at most 10; `PendingSessionTTL` is `PendingTTL`, `AccountLabel` removed, `Issuer` required, `Digits` 6 or 8, `Period` at most 3600, `BackupCodeCount` at most 20) |
| verify body `{"code","isBackupCode"}` | `{"code","backupCode"}`; backup codes only with `true`, no fallthrough |
| `TFA.Required` (403 `tfa_setup_required`) | `TOTP.Required` (202 `{"challenge":"totp_setup"}` at login) |
| `EnableRegistration` | `EnableRegistration` (still off by default) |
| `SessionName`, `SessionExpiration` | `StoreOptions.CookieName`, `MaximumAge` |
| `SessionSecretKey` (64 bytes) | removed |
| `SessionEncryptionKey` (32 bytes) | `StoreOptions.EncryptionKey` |
| `CookieSecure`, `CookieHttpOnly`, `CookieSameSite`, `CookiePath`, `CookieDomain` | `InsecureCookie` (inverted), always HttpOnly, `SameSite`, `CookiePath`, `CookieDomain` |
| `PasswordRequirements` | `Policy` (`MinLength` is `MinimumLength`, `RequireNumbers` is `RequireDigit`) |
| `Messages` | removed (clients map the codes) |
| `HashingParams`, `Params`, `DefaultPasswordHashingParams` | `HashParameters`, `Parameters`, `DefaultParameters()` |
| `LegacyPasswordVerifier`, `BcryptVerifier` | `LegacyVerifier`, `VerifyBcrypt` |
| `HashPassword`, `VerifyPassword` (returned `Params`) | `Hash`, `Verify` (returns `(bool, error)`) |
| `GenerateSessionSecretKey`, `GenerateSessionEncryptionKey`, `GenerateSessionKey` | `openssl rand -base64 32` + `session.ParseKey` |
| `NewMemoryStorage` | `password.NewMemoryStorage` |
| `Storage` without ctx; `UpdateUser`, `DeleteUser` | ctx on every method; `UpdatePasswordHash` (compare-and-swap); new `ConsumeTOTPStep`; `SetTOTP` returns `(bool, error)` and enables only while TOTP is off; delete removed; `CreateUser` must return `ErrUserExists`; usernames and emails unique and looked up ignoring case |
| `User.CreatedAt/UpdatedAt/IsTechnicalUser/APIKeyHash/TOTPEnrolledAt/TOTPFailedAttempts` | not part of `password.User`; keep them in your own table |
| routes `/auth/login`, `/logout`, `/register`, `/me`, `/tfa/{setup,enable,disable,verify}` | `/auth/password/login`, `/logout`, `/register`, `auth.IdentityHandler()` at your path, `/auth/password/totp/{setup,enable,disable,verify}` + `GET /auth/password/totp` |
| error body `{"error","message"}`, codes `tfa_*`, `unauthorized`, `invalid_request` | `{"code","message"}`, codes `totp_*`, `unauthenticated`, `invalid_request` |
| login 202 `{"data":{"tfaRequired":true}}`, success `{"message","data":UserResponse}` | 202 `{"challenge":"totp"}`, 200 `IdentityResponse`; logout 204 |
| `ErrInvalidCredentials`, ... | `auth.ErrUnauthenticated` etc. plus codes; storage sentinels `password.ErrUserNotFound`, `ErrUserExists`, `ErrTOTPAttemptsExhausted` |

### Recipe

1. `go get github.com/govengers/auth@v1`, change imports, drop `go-basicauth` and `gorilla/sessions` from `go.mod`.
2. Generate `SESSION_ENCRYPTION_KEY` with `openssl rand -base64 32`; remove the signing key.
3. Pick a backend: `session.NewMemoryBackend(nil)` for one replica, `redisbackend.New` for several.
4. Port your `Storage`. All methods take a `context.Context` first. Keep `CreateUser`, `GetUserBy*`, `ConsumeTOTPAttempt`, `ResetTOTPAttempts`, `ConsumeBackupCode`, `ClearTOTP` (same atomic contracts). `SetTOTP` now returns `(bool, error)` and enables TOTP only while it is off, check and write in one step: `UPDATE users SET totp_enabled = true, totp_secret = $2, backup_code_hashes = $3, failed = 0 WHERE id = $1 AND NOT totp_enabled`, one row is `true`, zero rows `false` (a concurrent enrollment won; the provider answers 409 `totp_already_enabled`). Replace `UpdateUser` with `UpdatePasswordHash(ctx, id, currentHash, newHash)`: write only while the stored hash still equals `currentHash` (`UPDATE users SET password_hash = $3 WHERE id = $1 AND password_hash = $2`); zero rows is not an error. Return `password.ErrUserExists` for a duplicate username or email (map the unique constraint; the library no longer pre-checks). Usernames and emails are unique and looked up ignoring case: unique indexes on `lower(username)` and `lower(email)`, lookups `WHERE lower(username) = lower($1)`; the provider passes identifiers as typed. Add `ConsumeTOTPStep(ctx, id, step time.Time) (bool, error)` on a new nullable `totp_step` column: `UPDATE users SET totp_step = $2 WHERE id = $1 AND (totp_step IS NULL OR totp_step < $2)`, one row is `true`, zero rows `false`; `SetTOTP` and `ClearTOTP` leave the column alone. Delete `DeleteUser`. Map your columns onto `password.User` (`ID`, `Username`, `Email`, `PasswordHash`, `TOTPEnabled`, `TOTPSecret`, `BackupCodeHashes`); other columns stay yours. The attempts counter can keep the same SQL, e.g. `UPDATE users SET failed = failed + 1 WHERE id = $1 AND failed < $2 RETURNING $2 - failed` (no row: `ErrTOTPAttemptsExhausted`); give your admins a way to call `ResetTOTPAttempts`, it is now the only unlock besides a verified code.
5. Build store, provider and Guard; replace `RegisterRoutes()` and `RequireAuth()`:

```go
// before
handler, _ := basicauth.NewHandler(&basicauth.Options{Engine: r, Storage: storage, Settings: settings, UserKey: UserKey})
handler.RegisterRoutes() // also r.Use(handler.RequireAuth())
r.GET("/profile", handler.RequireAuth(), profile)

// after
store := must(session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key}))
provider := must(password.New(&password.Options{
	Sessions: store,
	Storage:  storage,
	Policy:   password.Policy{MinimumLength: 8, RequireUppercase: true, RequireLowercase: true, RequireDigit: true},
	TOTP:     password.TOTPOptions{Enabled: true, Issuer: "MyApp"},
}))
guard := must(session.NewGuard(&session.GuardOptions{Store: store, Refreshers: []session.Refresher{provider}}))

ginadapter.RegisterRoutes(r, provider.Routes()) // on the engine root
protected := r.Group("/", ginadapter.Middleware(guard.RequireAPI()))
protected.GET("/profile", profile)              // auth.IdentityFrom(c.Request.Context())
protected.GET("/me", gin.WrapH(auth.IdentityHandler()))
```

6. Replace `GetUserFromContext(c)` with `auth.IdentityFrom(c.Request.Context())`, or add the [app-user middleware](wiki/Authorization.md#your-application-user) when you used `UserTransformer`.
7. Frontend: new login path and response, `tfa` to `totp`, new error shape and codes, `userId` instead of `id`, `backupCode: true` for backup codes (a separate "use a backup code" input), `{}` as the body of `/totp/setup`.
8. `PathPrefix: "/auth"` keeps `/auth/login`, `/auth/logout` and `/auth/register`; the TOTP routes still change. An `AuthenticationBaseUrl` with a trailing `/` or other characters than `A-Z a-z 0-9 . _ ~ -` per segment must be changed.
9. Deploy; users log in again.

## 2. oidc-fwd-auth library (v0.9.x) to `oidc`

### Behaviour changes

- **PKCE (S256) and nonce** are always on; state, nonce and verifier are bound to the server-side login session (single use, 10 minutes), which is what makes several replicas work.
- **Redirect URI is derived**: `ExternalURL + PathPrefix + "/callback"`, with `PathPrefix` defaulting to `/auth/oidc/<name>`. Register the new URI at the IdP. For a single provider you can keep the old URL with `PathPrefix: "/auth/oidc"`. The end-session endpoint is discovered (`LogoutUri` is gone); `PostLogoutURL` replaces `PostLogoutRedirectUri`.
- **Several IdPs**: one `oidc.New` per IdP with distinct `Name`s (`[a-z0-9-]{1,32}`; `password`, `github`, `apikey`, `session` and `jwt` are reserved) on one `session.Store`. `MultiHandler`, `AddProvider` and the login selector are gone; link to `provider.LoginURL()`.
- **Discovery**: besides the issuer, the endpoints discovery names (authorization, token, JWKS and, when present, end session) must be `https`, or `http` on a loopback host; `oidc.New` fails otherwise, before any credential is sent.
- **Callback failures**: the IdP rejecting the code (an error answer below 500) is 401 `login_failed`, a 5xx answer or an IdP that cannot be reached is 500; an ID token without `sub` is refused, and one that does not verify is 401 `login_failed` with a fixed reason (expired, or verification) on the outcome. The new `ErrorURL` (a path or an absolute URL, no fragment) turns every callback failure into a redirect to `ErrorURL?code=<code>` (`code=internal` for a 500). `PostLogoutURL` may now be a path too; it is made absolute with `ExternalURL`.
- **Client authentication** at the token endpoint is fixed from discovery: HTTP Basic, unless the IdP lists only `client_secret_post`. oauth2's auto-detection (which resends a failed exchange with the other style) is not used.
- **Logout** sends the stored ID token as `id_token_hint`. Without one (the local session had already expired, or the IdP has no `end_session_endpoint`) it redirects straight to `PostLogoutURL` and the IdP session stays. A request from another site (`Sec-Fetch-Site: cross-site`) is refused with 403 and ends nothing; front-channel logout from the IdP's iframe still works.
- **Identity, not `SessionData`.** `IDToken` and `AccessTokenClaims` are not exposed; the raw ID token stays server-side (used as `id_token_hint` at logout). Claims are in `Identity.Claims`.
- **Roles and groups**: realm roles (`realm_access.roles`), client roles (`resource_access.<ClientID>.roles`) and groups (`groups`) are read from the access token first and, per claim, from the ID token when the access token lacks it, as before; with Keycloak enrichment they are replaced by the Admin API's answer.
- **Keycloak** moved to `oidc/keycloak` (gocloak, resty and golang-jwt are gone). The default grant flips from `password` to `client_credentials`; the password grant breaks as soon as the admin user gets an OTP credential. A missing required role or group refuses the login with 403 and a generic body (`AuthorizationDeniedError` detail is no longer sent).
- **Google**: `AllowedEmailDomains` requires `email_verified` and a matching domain; the old mode admitted any Google account.
- **Userinfo**: `/userinfo` is replaced by `auth.IdentityHandler()` behind the Guard (public view, no raw claims).
- **Refresh**: the OIDC provider has no refresher (as before); the session lives until `MaximumAge` or logout. Front-channel logout needs `SameSite: http.SameSiteNoneMode` and HTTPS.
- **jwt**: RS512 only, jwx v3, no `jku` header, no generated key, default lifetime 5 minutes (was 30), `Sign` refuses an inactive identity (`auth.ErrForbidden`), no verifier cache or goroutine; `NewVerifier` fetches the JWKS once and fails fast, also when it holds no RSA key with an RSA signature `alg` (RS*, PS*), a `kid` and use `sig` or none, is no JSON JWK set or is larger than 1 MiB (other keys, `oct` included, and entries that do not parse are ignored). `Verify` requires `exp`, checks `nbf` and `iat` with 30 s skew and returns an `auth.Identity`; `RefreshInterval` is at least 1 minute (`LocalJwks`, `Cached`, `CacheSize`, `TTL` are gone). The middleware matches `Bearer` in any case and answers 401 with `WWW-Authenticate: Bearer`. Claims: `sub`, `provider`, `user_id`, `preferred_username`, `name`, `email`, `picture`, `roles`, `realm_roles`, `client_roles`, `groups`, `teams`, `permissions`, plus the other ID token claims; an ID token claim with one of these names, in any letter case, is never copied (an IdP `roles` claim does not become application roles).

### Symbol map

| Old | New |
|---|---|
| `oidc.NewHandler(&Options{Provider, Session, ...})` | `oidc.New(ctx, &oidc.Options{Name, Issuer, ClientID, ClientSecret, ExternalURL, Sessions, ...})` |
| `ProviderOptions.ClientId`, `RedirectUri`, `LogoutUri`, `Scopes`+`ExtraScopes`, `ClaimMapper` | `ClientID`, derived from `ExternalURL`, discovered `end_session_endpoint`, `Scopes`, `ClaimMapper` (returns `oidc.Profile`) |
| `PostLogoutRedirectUri`, `AuthBaseUrl`, `AuthBaseContextPath` | `PostLogoutURL`, `ExternalURL`, `PathPrefix` (default `/auth/oidc/<name>`) |
| `EnableUserInfoEndpoint`, `/userinfo` | `auth.IdentityHandler()` (no raw claims) |
| `SessionOptions{SecretSigningKey, SecretEncryptionKey, Name, Domain, MaxAge, Secure, SameSite, Backend, CacheSize, CacheTTL, Redis}` | `session.StoreOptions{-, EncryptionKey []byte, CookieName, CookieDomain, MaximumAge time.Duration, InsecureCookie, SameSite, Backend, -, -, redisbackend.New}`; `CacheSize` is `MemoryBackendOptions.MaximumSessions` |
| `ExternalSessionStore`, `MultiHandler`, `AddProvider`, `GetHandler`, `GetDefaultHandler`, `LoginURL`, `ProviderNames` | one `oidc.New` per IdP sharing one Store; `Provider.LoginURL()` |
| `GetUiAuthMiddleware`, `GetApiAuthMiddleware` | `guard.RequireUI()`, `guard.RequireAPI()` |
| gin keys `sessionData`, `realmRoles`, `clientRoles`, `groups`, `attributes`, `provider` | `auth.IdentityFrom(ctx)`: `OIDCRoles`, `OIDCClientRoles`, `Groups`, `Attributes`, `Provider` |
| `SessionData{Sub, Name, Username, Email, IDToken, Claims, AccessTokenClaims, RealmRoles, ClientRoles, Groups, Attributes}` | `auth.Identity{Subject, Name, Username, Email, -, Claims, -, OIDCRoles, OIDCClientRoles, Groups, Attributes}` |
| `SessionStore.GetSessionData(r)`, `Set/Get/PopStringValue`, flash | `store.Open(r)` + `Session.Identity/Put/Get/Pop` (prefix your own keys with `app.`) |
| `PostLoginHook(c, *SessionData) error` | `OnLogin auth.Hook` (return `&auth.Error{Kind: auth.ErrForbidden}` to refuse) |
| `PostLogoutHook(c)` | `OnLogout auth.LogoutHook` |
| `GocloakOptions{ServerURL, AuthMethod, ...}`, `FetchUserAuthorization`, `GocloakEnabled` | `keycloak.New(&keycloak.Options{URL, GrantType (default client_credentials), AuthenticationRealm, ...})`, `OnLogin: client.Enrich` |
| `AuthorizationDeniedError` (403 with detail) | `*auth.Error{Kind: ErrForbidden, Reason}` (403 without detail) |
| `ErrSessionRevoked` | `session.ErrRevoked` |
| `jwt.NewSigner(&SignerOptions{Algorithm, JwtIssuer, JwtPrivateKey})`, `NewToken`, `SignToken`, `Token`, `Jwks` | `jwt.NewSigner(&jwt.SignerOptions{PrivateKey, Issuer, Audience, Lifetime})`, `Sign(identity)`, `JWKSHandler()` |
| `jwt.NewHandler(&HandlerOptions{JwksUrl, JwksRefreshInterval, LocalJwks, Cached, CacheSize, TTL, HeaderKey})`, `GetUserFromRequest`, `jwt.User` | `jwt.NewVerifier(ctx, &jwt.VerifierOptions{JWKSURL, Issuer, Audience, RefreshInterval, HeaderName})`, `Middleware()` / `Verify`, `auth.Identity` |
| routes `/auth/oidc/{login,callback,logout,frontchannel-logout}` | `/auth/oidc/<name>/...` (register the new callback at the IdP) |

### Recipe

1. `go get github.com/govengers/auth@v1`; drop `oidc-fwd-auth`, `gocloak` and `gorilla/sessions`.
2. Generate `SESSION_ENCRYPTION_KEY` (`openssl rand -base64 32`) and build the store. A Redis setup becomes `redisbackend.New(&redisbackend.Options{Client: client, KeyPrefix: "..."})` with a go-redis client you own.
3. Replace the handler:

```go
// before
oidcHandler, _ := oidc.NewHandler(&oidc.Options{
	Provider: &oidc.ProviderOptions{Issuer: issuer, ClientId: "my-app", ClientSecret: secret,
		RedirectUri: "https://my-app.com/auth/oidc/callback", LogoutUri: logoutURL},
	Session:             &oidc.SessionOptions{SecretSigningKey: signing, SecretEncryptionKey: encryption, Name: "oidc_session", MaxAge: 86400, Secure: true},
	AuthBaseUrl:         "https://my-app.com",
	AuthBaseContextPath: "/auth/oidc",
	Gocloak: &oidc.GocloakOptions{ServerURL: kcURL, Realm: "my-realm", AuthMethod: "client_credentials",
		ClientID: "my-admin-client", ClientSecret: kcSecret, ClientRolesClientID: "my-app", RequiredRealmRoles: []string{"user"}},
})
api.Use(oidcHandler.GetApiAuthMiddleware())

// after
enricher := must(keycloak.New(&keycloak.Options{URL: kcURL, Realm: "my-realm",
	ClientID: "my-admin-client", ClientSecret: kcSecret, ClientRolesClientID: "my-app", RequiredRealmRoles: []string{"user"}}))
provider := must(oidc.New(ctx, &oidc.Options{
	Name: "keycloak", Issuer: issuer, ClientID: "my-app", ClientSecret: secret,
	ExternalURL: "https://my-app.com",
	PathPrefix:  "/auth/oidc", // optional: keeps the old callback URL at the IdP
	Sessions:    store,
	OnLogin:     enricher.Enrich,
}))
guard := must(session.NewGuard(&session.GuardOptions{Store: store, LoginURL: provider.LoginURL()}))
ginadapter.RegisterRoutes(engine, provider.Routes())
api.Use(ginadapter.Middleware(guard.RequireAPI()))
```

4. Move `PostLoginHook`/`PostLogoutHook` logic into `OnLogin`/`OnLogout`; return a modified `identity.Clone()`; to chain with Keycloak, call `enricher.Enrich` first inside your closure.
5. Replace gin key reads with `auth.IdentityFrom(c.Request.Context())` (fields in the symbol map). Use `authorization.HasOIDCRole`, `HasOIDCGroup` and `ginadapter.Require` for role gates.
6. Replace `jwt.NewHandler` in backends with `jwt.NewVerifier(ctx, &jwt.VerifierOptions{JWKSURL, Issuer})`; the middleware puts an `auth.Identity` in the context.
7. Register the new callback (and front-channel logout and post-logout URLs, if changed) at the IdP, deploy; users log in again.

## 3. github-fwd-auth library (v1.4.x) to `github`

### Behaviour changes

- **Teams are mandatory.** `AllowedTeams` needs at least one `org/team-slug`. The old binary README says an empty `ALLOWED_GITHUB_TEAMS` admitted every GitHub user; there is no such mode any more.
- **Teams are filtered.** `Identity.Teams` holds only teams in `AllowedTeams`, `AdminTeams` and `RelevantTeams` (lower-case, sorted, unique). The caller's slices are never modified. Admin team members get `auth.RoleAdmin` in `Roles`; as before, they also need an allowed team. Configured teams must be `org/team-slug` (one `/`, no white space).
- **No profile cache, no `UserProfile`.** The 40-field profile, `Team`, `Organization`, `Plan` and `GetTeamSlugs` are gone; the identity has `Username` (login), `Name`, `Email` (may be empty), `Picture`. For anything else call GitHub with `provider.HTTPClient(ctx, current)`, which sends the user's token to the `APIURL` host only (a redirect to another host, e.g. an archive download or `uploads.github.com`, goes without it). The token stays in the server-side session.
- **Freshness.** Teams are refetched by the Guard's refresher every `RefreshInterval` (1 minute, the old cache TTL) and by `POST {prefix}/refresh-teams`. A user who left every allowed team loses the session. A refresh failing otherwise (GitHub outage, rate limit) keeps the teams, at most for `GuardOptions.MaximumUnverifiedAge` (default 1 hour) since the last successful one; then the session ends. refresh-teams keeps a change another request saved meanwhile and answers 409 `conflict` when that change touched the membership, the admin role or the user, or when the session changed twice during the call. Like logout it refuses a cross-site request (`Sec-Fetch-Site: cross-site`) with 403.
- **Routes** move under `PathPrefix` (default `/auth/github`): `GET /login`, `GET /callback`, `GET /logout` (was `POST`), `POST /refresh-teams`. `PathPrefix: "/auth"` keeps `/auth/login`, `/auth/callback` and `/auth/refresh-teams`, so the OAuth app's callback URL stays valid. The userinfo route is replaced by `auth.IdentityHandler()`. The Origin check of the old POST logout is replaced by a Fetch Metadata check: a `GET /logout` the browser marks `Sec-Fetch-Site: cross-site` is refused with 403. A logout link from another site (a portal on another domain) must move onto the app's host.
- **Login redirect** uses `ExternalURL` (absolute), as `BaseURL` did. `PostLogoutURL` and `ErrorURL` are made absolute too and refuse a fragment: a hash-route error page such as `/#/error` must become a real path. `ErrorURL` now also receives server-side failures as `?code=internal`.
- **Code exchange**: GitHub refusing the code is 401 `login_failed`; a GitHub 5xx or outage is 500.
- **URLs** must be `https` with a host name, except loopback hosts (`localhost`, `127.0.0.0/8`, `::1`).
- **Cookie** defaults: name `auth_session` (sent as `__Host-auth_session`, see "Changes for every library"), host-only (was `session_id` on `localhost`), lifetime 24 h (was 7 days, `SessionMaxAge`).
- **JWT**: `sub` is the numeric GitHub user ID, the login is `preferred_username`, `uid` is removed, `teams` is the filtered list; see section 2 for the other JWT changes.
- **API keys** moved to `apikey`: named, at least 16 bytes, names and secrets unique, no surrounding whitespace, optional `Roles` and `Permissions`. A key no longer bypasses admin checks. `Authorization: Bearer` is matched in any case, and a bearer value that is no key is 401 `invalid_api_key`, even with a valid session cookie. The `Resolver` returns an `*auth.Identity` with `Active` set (an inactive one fails every check but `IsAuthenticated`); return an error matching `auth.ErrUnauthenticated` for unknown keys, any other error answers 500. The error's text lands in the outcome and on the wide event, so it must not repeat the key.
- **Scopes** must include one that lists the user's teams (`read:org`, `write:org`, `admin:org`, `user` or `repo`); `github.New` refuses others. The old `user:email, read:org` passes.
- **Access levels become permissions.** build-api kept `read_only`/`read_write` in `ResolvedAPIKey.Data` and refused non-GET requests of read-only keys in its own middleware. Now the resolver returns `Permissions`: `read_only` is `[*:read]`, `read_write` is `[*:write]`; gate routes with `ginadapter.RequireMethodPermission(resource)` (GET, HEAD, OPTIONS need read, everything else write) or `ginadapter.Require(authorization.HasPermission(resource, access))`. Browser sessions carry no permissions: grant them in `OnLogin` (e.g. `*:write` for allowed-team members) or compose `authorization.Any(authorization.HasRole(...), authorization.HasPermission(...))`.

### Symbol map

| Old | New |
|---|---|
| `githuboauth.Init(engine, &Config)` / `New(&Config)` + `GetMiddleware()` | `github.New(&github.Options{...})`, `ginadapter.RegisterRoutes`, `ginadapter.Middleware(guard.RequireUI())` |
| `Config.RedirectURI`, `AuthURL`, `TokenURL`, `DeviceAuthURL`, `GitHubAPIBaseURL`, `BaseURL` | derived, `AuthorizeURL`, `TokenURL`, removed, `APIURL`, `ExternalURL` |
| `LoginPath`, `CallbackPath`, `UserInfoPath`, `LogoutPath`, `RefreshTeamsPath` | `PathPrefix` (`/auth/github`); userinfo is `auth.IdentityHandler()`; logout is `GET` |
| `AllowedTeams`, `AdminTeams`, `RelevantTeams` | same (never mutated; `Teams` filtered to these) |
| `AllowedAPIKeys`, `APIKeyResolver`, `ResolvedAPIKey{Login, Teams, Data}` | `apikey.Options{Keys: []apikey.Key{Name, Secret, Roles, Permissions}, Resolver}` returning `*auth.Identity{Subject/Username, Teams, Permissions, Data}` |
| access level in `ResolvedAPIKey.Data` (`read_only`, `read_write`) + an app middleware refusing non-GET | `Identity.Permissions` `[*:read]` / `[*:write]` + `ginadapter.RequireMethodPermission(resource)` |
| `GetApiKeyAuthMiddleware(keys)` | `keys, err := apikey.New(...)`, then `keys.Middleware()` |
| `SessionSecretKey`, `SessionEncryptionKey`, `CookieName`, `CookieDomain` (default localhost), `SessionMaxAge *int`, `CookieInsecure` | removed, `StoreOptions.EncryptionKey`, `CookieName`, `CookieDomain` (default host-only), `MaximumAge`, `InsecureCookie` |
| `Handle.IsAuthenticated(c)`, `IsAdmin(c)`, `GetRelevantTeams(c)` | `authorization.IsAuthenticated()`, `authorization.IsAdmin()`, `auth.IdentityFrom(ctx).Teams` |
| `GetAdminMiddleware()` | `ginadapter.Require(authorization.IsAdmin())` |
| `GetSessionStore().GetSession(c)`, `Session.GetHttpClient(ctx)`, `GetToken` | `store.Open(request)`, `provider.HTTPClient(ctx, current)` |
| `GetGitHubConnector`, `UserProfile`, `Team`, `Organization`, `Plan`, `GetTeamSlugs` | removed; `Identity.Teams`, `HTTPClient` for anything else |
| `GenerateSession*Key`, `EncodeKeyToBase64`, `DecodeKeyFromBase64` | `session.ParseKey` |
| `ErrSessionNotFound`, `ErrInvalidSession`, `ErrUserInfoNotCached` | `auth.ErrUnauthenticated` |
| github `pkg/jwt` (jwx v2) | `jwt` (jwx v3); JWT `sub` is the numeric ID, `preferred_username` the login, `uid` removed |

### Recipe

1. `go get github.com/govengers/auth@v1`; drop `github-fwd-auth` and `gorilla/sessions`.
2. Keep your base64 `SESSION_ENCRYPTION_KEY` if it is 32 bytes (`ParseKey` reads it), or generate a new one. Drop the secret key.
3. Replace `Init` or `New`:

```go
// before
handle, _ := githuboauth.Init(router, &githuboauth.Config{
	ClientID: id, ClientSecret: secret, RedirectURI: "https://example.com/auth/callback",
	Scopes: []string{"user:email", "read:org"}, AuthURL: authURL, TokenURL: tokenURL,
	AllowedTeams: []string{"my-org/my-team"}, SessionSecretKey: secretKey, SessionEncryptionKey: encryptionKey,
	CookieDomain: "example.com",
}) // every route on the engine now requires authentication

// after
provider := must(github.New(&github.Options{
	ClientID: id, ClientSecret: secret, ExternalURL: "https://example.com",
	AllowedTeams: []string{"my-org/my-team"}, Sessions: store,
}))
guard := must(session.NewGuard(&session.GuardOptions{
	Store: store, LoginURL: provider.LoginURL(), Refreshers: []session.Refresher{provider},
}))
ginadapter.RegisterRoutes(router, provider.Routes())
app := router.Group("/app", ginadapter.Middleware(guard.RequireUI()))
app.GET("/", dashboard) // auth.IdentityFrom(c.Request.Context()).Teams
```

4. Replace `GetSessionStore().GetSession(c)` and `sess.UserInformation.Profile.Login` with `auth.IdentityFrom(c.Request.Context()).Username`.
5. Replace `AllowedAPIKeys` with `apikey` keys (named, 16 bytes or longer) and mount `keys.Middleware()` before the Guard. A key no longer bypasses admin checks; give it `Roles: []string{auth.RoleAdmin}` if it must, or `Permissions` and gate the routes with them. A resolver that stored access levels returns `Permissions` (`*:read`, `*:write`).
6. Change the GitHub OAuth app's callback URL to `https://example.com/auth/github/callback`, or set `PathPrefix: "/auth"` to keep it. `Scopes` default to `read:org`, which the team lookup needs; `Identity.Email` is the profile's email and may be empty.
7. Deploy; users log in again.

## 4. The forward-auth binaries to `forwardauth`

Both images become `ghcr.io/govengers/forwardauth:<version>` (distroless `static-debian13`, non-root, amd64 and arm64; tags `:1.0.0`, `:1.0`, `:1`, `:latest`, and `:main` from the main branch), started with `PROVIDER=oidc` or `PROVIDER=github`. Password login is not offered, and one instance runs one provider (the Google multi-provider mode is gone: Google is `OIDC_ISSUER=https://accounts.google.com`, `OIDC_CLAIM_MAPPER=google`, `OIDC_ALLOWED_EMAIL_DOMAINS`).

### Behaviour changes

- **Routing.** The check endpoints are `{PATH_PREFIX}/ui` and `{PATH_PREFIX}/api` (default `/auth/ui`, `/auth/api`). Login, callback and logout are served on `{PATH_PREFIX}/oidc/<OIDC_NAME>/...` or `{PATH_PREFIX}/github/...` and must be routed to the service by their own Traefik router without the forwardAuth middleware, which excludes the checks and probes: ``Host(`<host>`) && PathPrefix(`/auth`) && !Path(`/auth/ui`) && !Path(`/auth/api`) && !Path(`/auth/health`) && !Path(`/auth/ready`)`` (a public check answer would hand its bearer JWT to same-origin scripts, a public `/ready` costs a Redis `PING` per anonymous call). The old github image dispatched them from the check endpoint by `X-Forwarded-Uri`; that dispatch is gone. Logout links must live on the app's own site: a cross-site request (`Sec-Fetch-Site: cross-site`) to `/logout` is refused with 403.
- **oidc-fwd-auth users**: check addresses stay `/auth/ui` and `/auth/api`; the callback becomes `/auth/oidc/<OIDC_NAME>/callback` (default `/auth/oidc/oidc/callback`), JWKS moves from `/auth/JWKS` to `/auth/jwks`. **JWT is no longer always on:** set `JWT_ENABLED=true`.
- **github-fwd-auth users**: `/ui-auth` and `/api-auth` become `/auth/ui` and `/auth/api`, `/health` becomes `/auth/health` (probes), `/JWKS` becomes `/auth/jwks`, the OAuth callback becomes `/auth/github/callback`. Add the `/auth` router. **`GITHUB_ALLOWED_TEAMS` is required** (an empty `ALLOWED_GITHUB_TEAMS` used to admit every GitHub user).
- **JWT** (backends). Lifetime 5 minutes (was 30), minted per request, `JWT_LIFETIME_SECONDS` to change it. `JWT_ISSUER` defaults to `EXTERNAL_URL` (oidc-fwd-auth defaulted to `oidc-fwd-auth`): update the backends' expected issuer or set `JWT_ISSUER` to the old value. `JWT_PRIVATE_KEY` is required when JWT is enabled; there is no generated key, so every replica and every restart signs with the same key. OIDC claims are kept (all ID token claims plus `provider`, `user_id`, `realm_roles`, `client_roles`, `groups`, `permissions`), but `iss sub aud exp nbf iat jti nonce at_hash c_hash auth_time sid azp realm_access resource_access` (read `realm_roles` and `client_roles` instead) and every claim name the identity owns (`roles`, `groups`, `preferred_username`, ...) are never copied from the ID token. Backends verifying with `jwt.Verifier` need `exp` (always set by the proxy). GitHub: `sub` is the numeric ID, `preferred_username` the login, `uid` is gone, `teams` holds only allowed, admin and relevant teams, `roles` contains `admin` for admin teams. The `kid` is the RFC 7638 thumbprint and the JWKS has no `jku`; the full claim set is in [docs/wiki/Forward-Auth-Configuration.md](wiki/Forward-Auth-Configuration.md#jwt).
- **API keys** (`API_KEYS`): they need `API_KEYS_ENABLED=true`; without the flag `API_KEYS` and `API_KEY_PERMISSIONS` are ignored, and with it at least one key is required. Entries are `name:secret` (split at the first `:`); names and secrets are unique, the secret is at least 16 bytes and must not contain `,`. `Authorization: Bearer` is matched in any case. With API keys enabled, a request whose `Authorization: Bearer` value is not a configured key is refused with 401 `invalid_api_key` on both checks, even with a valid session cookie: an SPA that sends its own bearer tokens through the proxy cannot use API keys. The JWT `sub` is the key name. Keys carry no roles, so they no longer pass admin checks. They carry the permissions given in `API_KEY_PERMISSIONS` (`name=perm+perm`, comma-separated, e.g. `ci=builds:write+deployments:read`) as the JWT `permissions` claim; a key without an entry has none. **The old keys had unrestricted access: `<name>=*:write` reproduces that** for backends that check permissions.
- **Traefik hardening**: set `trustForwardHeader: false` and `maxResponseBodySize` on both forwardAuth middlewares and `aliasHeadersStrategy: delete` on the entrypoints ([Traefik settings](wiki/Forward-Auth-Configuration.md#traefik-settings)). With `authResponseHeaders: [Authorization, X-API-Key]` Traefik deletes a client-sent `Authorization` and `X-API-Key` before the app sees them, also when JWT is off, so a raw API key stops at forwardauth.
- **Cookies and sessions**: see "Changes for every library". `SESSION_SAME_SITE` takes `lax` (default) or `none`; `strict` is refused, because the browser withholds a strict cookie, and the login state with it, on the redirect back from the provider. Several replicas need `SESSION_REDIS_ENABLED=true`; without Redis run exactly one replica. With Redis the boot fails when it does not answer a `PING` within 5 s.
- **Readiness and metrics**: new `{PATH_PREFIX}/ready` (503 `{"code":"unavailable"}` during shutdown or when Redis is down; a failed check is a kept wide event) and a metrics listener on `METRICS_PORT` (9090, must differ from `PORT`) that serves only `GET /metrics`. Shutdown answers readiness 503 for `SHUTDOWN_DELAY_SECONDS` (default 5, at most 10) before draining, so `docker stop` takes about 5 s. Logs are wide events on stdout, sampled by `WIDE_EVENT_SAMPLE_RATE`; `LOG_LEVEL` is gone. Unknown paths answer 404 JSON `{"code":"not_found"}`, a known route with a trailing `/` too (no redirect).
- **Configuration errors** stop the process at startup, listing every missing or invalid variable: also an `EXTERNAL_URL` with a path (it is the origin, scheme and host only), a plain `http` `EXTERNAL_URL` whose host is not loopback without `SESSION_INSECURE_COOKIE=true` (browsers drop the `Secure` cookie there), an unparsable `SESSION_ENCRYPTION_KEY`, `PORT` equal to `METRICS_PORT`, a `PATH_PREFIX` with a `.` or `..` segment, `KEYCLOAK_ENABLED` without `PROVIDER=oidc`, `API_KEYS_ENABLED=true` without keys, an `API_KEYS` entry without `:` (reported by position, never echoed), a secret that is too short or used twice, a bad `API_KEY_PERMISSIONS` entry and a `JWT_HEADER` that is no header name or one the answer sets itself (`Cache-Control`, `Set-Cookie`, ...). `GITHUB_SCOPES` must include `read:org`, `write:org`, `admin:org`, `user` or `repo`.

### Environment variables

| oidc-fwd-auth | github-fwd-auth | forwardauth |
|---|---|---|
| - | - | `PROVIDER` (new, required) |
| `DEPLOYMENT_IMAGE_TAG` | - | removed (version via ldflags) |
| `LOG_LEVEL` | `LOG_LEVEL` | removed (wide events; `WIDE_EVENT_SAMPLE_RATE`) |
| `DEV` | `DEV` | `DEV_MODE` |
| `PORT` | `PORT` | `PORT` (+ `METRICS_PORT`) |
| `HEALTH_ENDPOINT`, `FWD_AUTH_API_ENDPOINT`, `FWD_AUTH_UI_ENDPOINT`, `JWKS_ENDPOINT`, `OIDC_ENDPOINTS_BASE_CONTEXT_PATH` | `/health`, `/api-auth`, `/ui-auth`, `/JWKS` (fixed) | `PATH_PREFIX` + `/health`, `/api`, `/ui`, `/jwks`, `/oidc/<OIDC_NAME>` |
| `ENABLE_USERINFO_ENDPOINT` | - | `IDENTITY_ENDPOINT_ENABLED` |
| `OIDC_ENDPOINTS_BASE_URL` | `BASE_URL` | `EXTERNAL_URL` (required; an origin, no path) |
| `SESSION_SIGNING_KEY` | `SESSION_SECRET_KEY` | removed |
| `SESSION_ENCRYPTION_KEY` (32 chars) | `SESSION_ENCRYPTION_KEY` (base64) | `SESSION_ENCRYPTION_KEY` (base64 of 32 bytes) |
| `SESSION_NAME` | `SESSION_COOKIE_NAME` | `SESSION_COOKIE_NAME` |
| `SESSION_DOMAIN` (default localhost) | `COOKIE_DOMAIN` (default localhost) | `SESSION_COOKIE_DOMAIN` (default host-only) |
| `SESSION_MAX_AGE` | `SESSION_MAX_AGE` | `SESSION_MAXIMUM_AGE_SECONDS` |
| `SESSION_SECURE` | `COOKIE_INSECURE` | `SESSION_INSECURE_COOKIE` |
| `SESSION_CACHE_SIZE` | - | removed |
| `SESSION_REDIS_ENABLED`, `_HOST` + `_PORT`, `_PASSWORD`, `_DB`, `_KEY_PREFIX` | - | `SESSION_REDIS_ENABLED`, `_ADDRESS`, `_PASSWORD`, `_DATABASE`, `_KEY_PREFIX` |
| `OIDC_WELL_KNOWN_URL` | - | `OIDC_ISSUER` (the well-known URL without `/.well-known/openid-configuration`) |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_SCOPES` | `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_SCOPES` | `OIDC_*` / `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_SCOPES` |
| `OIDC_REDIRECT_URI`, `GOOGLE_REDIRECT_URI` | `OAUTH_REDIRECT_URI` | removed (derived; register `EXTERNAL_URL/auth/oidc/<name>/callback` or `EXTERNAL_URL/auth/github/callback`) |
| `OIDC_LOGOUT_URL` | - | removed (discovered); `OIDC_POST_LOGOUT_URL` |
| `KEYCLOAK_SERVER_URL`, `KEYCLOAK_AUTH_METHOD` (default password) | - | `KEYCLOAK_URL`, `KEYCLOAK_GRANT_TYPE` (default client_credentials) |
| other `KEYCLOAK_*` | - | unchanged names (+ `KEYCLOAK_AUTHENTICATION_REALM`) |
| `GOOGLE_ENABLED`, `GOOGLE_CLIENT_ID/SECRET/SCOPES`, `AUTH_DEFAULT_PROVIDER`, `AUTH_LOGIN_SELECTOR_URL` | - | removed: one provider per instance; Google via `OIDC_ISSUER`, `OIDC_CLAIM_MAPPER=google`, `OIDC_ALLOWED_EMAIL_DOMAINS` |
| - | `OAUTH_PROVIDER_AUTH_URL`, `OAUTH_PROVIDER_TOKEN_URL`, `GITHUB_API_BASE_URL` | `GITHUB_AUTHORIZE_URL`, `GITHUB_TOKEN_URL`, `GITHUB_API_URL` (defaults github.com) |
| - | `OAUTH_PROVIDER_DEVICE_AUTH_URL` | removed |
| - | `ALLOWED_GITHUB_TEAMS`, `ADMIN_GITHUB_TEAMS` | `GITHUB_ALLOWED_TEAMS` (required), `GITHUB_ADMIN_TEAMS`, `GITHUB_RELEVANT_TEAMS` |
| (always signed) | `CREATE_JWT` | `JWT_ENABLED` (default false; oidc users set true) |
| - | `JWT_ALGORITHM` | removed (RS512) |
| `JWT_PRIVATE_KEY` (empty = generated) | `JWT_PRIVATE_KEY` | `JWT_PRIVATE_KEY` (required when enabled) |
| `JWT_ISSUER` (default oidc-fwd-auth) | `JWT_ISSUER` | `JWT_ISSUER` (default `EXTERNAL_URL`) + `JWT_AUDIENCE`, `JWT_LIFETIME_SECONDS`, `JWT_HEADER` |
| - | `API_KEYS` (secrets) | `API_KEYS_ENABLED=true` + `API_KEYS` (`name:secret` entries; carry no roles; ignored without the flag) |
| - | (static keys had unrestricted access) | `API_KEY_PERMISSIONS` (`name=perm+perm`); `name=*:write` reproduces the old unrestricted key for backends that check permissions |
| - | `github-fwd-auth.env` dotenv | `.env` in the working directory (development only) |

Notes: the old github image already took a base64 32-byte `SESSION_ENCRYPTION_KEY`, so it works unchanged; for an old 32-character oidc key `printf %s "$OLD" | base64` keeps the value, but generating a fresh key costs nothing because every session ends anyway. `OIDC_NAME` allows `[a-z0-9-]{1,32}`.

### Recipe: oidc-fwd-auth image

1. Set `PROVIDER=oidc`, `EXTERNAL_URL` (the old `OIDC_ENDPOINTS_BASE_URL`, scheme and host only), `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and a new `SESSION_ENCRYPTION_KEY`; delete `SESSION_SIGNING_KEY`, `SESSION_CACHE_SIZE`, `OIDC_REDIRECT_URI`, `OIDC_LOGOUT_URL`, `LOG_LEVEL`, `DEPLOYMENT_IMAGE_TAG`.
2. Rename the rest per the table (`SESSION_NAME`, `SESSION_MAXIMUM_AGE_SECONDS`, `SESSION_SECURE` inverted to `SESSION_INSECURE_COOKIE`, Redis `_HOST`+`_PORT` to `_ADDRESS`, `_DB` to `_DATABASE`). Use a new `SESSION_REDIS_KEY_PREFIX` (default `forwardauth`).
3. JWT: `JWT_ENABLED=true`, `JWT_PRIVATE_KEY` from `openssl genrsa -out jwt.pem 3072` (the old default was a key generated per start), and either `JWT_ISSUER=oidc-fwd-auth` or the new issuer in every backend.
4. Keycloak: `KEYCLOAK_SERVER_URL` to `KEYCLOAK_URL`; `KEYCLOAK_AUTH_METHOD` to `KEYCLOAK_GRANT_TYPE`. If you relied on the old `password` default, either set `KEYCLOAK_GRANT_TYPE=password` or move to a service-account client with the `realm-management` roles `view-users`, `query-users`, `view-clients`, `query-clients`, `query-groups`.
5. Google: drop `GOOGLE_*` and the login selector; run one instance per IdP.
6. IdP: add `https://<host>/auth/oidc/<OIDC_NAME>/callback` as redirect URI (and `.../frontchannel-logout` and the post-logout URL if used).
7. Traefik: keep the `/auth` router but exclude the checks and probes from it (rule under "Routing"), keep the `/auth/ui` and `/auth/api` middlewares, apply the hardening above; point backends' JWKS URL at `/auth/jwks`.
8. Roll out; users log in again.

### Recipe: github-fwd-auth image

1. Set `PROVIDER=github`, `EXTERNAL_URL` (the old `BASE_URL`, scheme and host only), `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` (the old `OAUTH_*`), `GITHUB_SCOPES` (default `read:org`, needed for the team lookup), **`GITHUB_ALLOWED_TEAMS`**, `GITHUB_ADMIN_TEAMS`, and `GITHUB_RELEVANT_TEAMS` for every other team a backend reads from the JWT. Delete `OAUTH_REDIRECT_URI`, `OAUTH_PROVIDER_*`, `SESSION_SECRET_KEY`, `JWT_ALGORITHM`, `LOG_LEVEL`.
2. Sessions: keep or regenerate `SESSION_ENCRYPTION_KEY`; `COOKIE_DOMAIN` becomes `SESSION_COOKIE_DOMAIN` (leave empty for a host-only cookie), `COOKIE_INSECURE` becomes `SESSION_INSECURE_COOKIE`, `SESSION_MAX_AGE` becomes `SESSION_MAXIMUM_AGE_SECONDS` (default is now 86400; set `604800` to keep a week). For several replicas enable Redis.
3. JWT: `CREATE_JWT` becomes `JWT_ENABLED`; set `JWT_PRIVATE_KEY` and `JWT_ISSUER` (now defaults to `EXTERNAL_URL`). Backends read the login from `preferred_username` and the numeric ID from `sub`.
4. `API_KEYS`: set `API_KEYS_ENABLED=true`, rewrite the keys as `name:secret` with unique secrets of 16 bytes or more; add `API_KEY_PERMISSIONS` (`name=*:write` for the old unrestricted access, or narrower permissions) for backends that check permissions.
5. GitHub OAuth app: set the callback URL to `https://<host>/auth/github/callback`.
6. Traefik: add the `/auth` router from "Routing" (without the checks and probes) to the forwardauth service (no forwardAuth middleware on it); change the middleware addresses to `http://<service>:8080/auth/ui` and `/auth/api` and apply the hardening above; backends fetch `/auth/jwks`. Probes use `/auth/health` and `/auth/ready`. Logout links point to `GET /auth/github/logout` and must live on the app's own site (a cross-site link gets 403).
7. Roll out; users log in again.

### Backends verifying the JWT

```go
verifier := must(jwt.NewVerifier(ctx, &jwt.VerifierOptions{
	JWKSURL: "http://forwardauth:8080/auth/jwks",
	Issuer:  "https://app.example.com", // JWT_ISSUER
}))
mux.Handle("GET /orders", verifier.Middleware()(orders))
```

Do not cache tokens beyond their `exp`; the proxy sends a fresh one with every request.

## Rolling back

The old modules and images keep working with their own keys and configuration. Sessions never carry over in either direction, so a rollback logs users out once more. Keycloak and most IdPs accept several redirect URIs, so old and new can be registered side by side; a GitHub OAuth app has one callback URL, so that switch happens at the cutover.

## After v1.0.0

Changes after the v1.0.0 release that can break an existing setup.

- **forwardauth `request.client_ip`**: the wide event's client IP is the peer address (Traefik's) unless `TRUSTED_PROXIES` lists the peer; it no longer believes a client's `X-Forwarded-For` or `X-Real-IP`. Set `TRUSTED_PROXIES` to Traefik's addresses or network to record the client again. An entry that is neither an IP nor a CIDR fails the boot.
