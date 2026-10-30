# Sessions

`session.Store` issues server-side sessions (the cookie carries 32 random bytes; values are AES-256-GCM sealed in a `Backend`). `session.Guard` authenticates requests by their session for every provider and re-validates identities through `Refresher`s.

## Store

`session.NewStore(&session.StoreOptions{...})`:

| Option | Default | Note |
|---|---|---|
| `Backend` | required | `session.NewMemoryBackend(nil)` or `redisbackend.New` |
| `EncryptionKey` | required | exactly 32 bytes, not one byte repeated (an all-zero placeholder is refused): `session.ParseKey(os.Getenv(...))`, generated with `openssl rand -base64 32`; same on every replica; changing it logs everyone out (no rotation list) |
| `CookieName` | `auth_session` | sent as `__Host-auth_session` while the cookie is Secure, host-only and on `/` (the default) |
| `CookieDomain`, `CookiePath` | host-only, `/` | either one drops the `__Host-` prefix |
| `SameSite` | `http.SameSiteLaxMode` | `None` for OIDC front-channel logout (https only); `Strict` only without OIDC and GitHub providers; `SameSiteDefaultMode` is refused |
| `InsecureCookie` | false | drops `Secure`; local plain-http development only |
| `MaximumAge` | 24 h | absolute lifetime from the login, never extended by activity or refresh |

Application code rarely touches the store directly: `store.Open(request)` returns the `session.Session` handle (for `github.Provider.HTTPClient` or own values via `Put`, `Get`, `Pop`; the key `identity` is reserved). `Session.SwapIdentity` saves a changed identity only while the session still holds the one you read (impersonation, own role changes).

## Guard

`session.NewGuard(&session.GuardOptions{...})`, one per application, shared by every provider:

- `RequireAPI()` answers 401 JSON without a session, 403 JSON for a refused identity.
- `RequireUI()` answers 302 to `LoginURL?return_to=<path>` without a session; 403 JSON for a refused identity (a redirect would loop).
- Both pass a request that already carries an identity (from `apikey` mounted in front) untouched.

| Option | Default | Note |
|---|---|---|
| `Store` | required | |
| `LoginURL` | `/` | `provider.LoginURL()` for OIDC and GitHub; your login page for password |
| `ReturnPathHeader` | request URI | forward auth uses `X-Forwarded-Uri` |
| `Refreshers` | none | password and GitHub providers; names must be unique |
| `RefreshInterval` | 1 min | |
| `MaximumUnverifiedAge` | 1 h | how long a failing (not refusing) refresh keeps the identity |

Tested excerpt of a Guard in front of API and UI routes ([session/example_test.go](../../session/example_test.go)):

```go
	serveMux := http.NewServeMux()
	serveMux.Handle("POST /login", loginHandler(store))
	serveMux.Handle("GET /api/me", guard.RequireAPI()(auth.IdentityHandler()))
	serveMux.Handle("GET /reports", guard.RequireUI()(http.NotFoundHandler()))
```

## Refresh

The Guard calls a provider's `Refresher` for identities whose last refresh is older than `RefreshInterval`, once per interval per session, detached from the request (30 s bound). Only the login and the Guard's own refresh count: `SaveIdentity` and `SwapIdentity` verify nothing and keep the last refresh time, so frequent application saves cannot postpone the Refresher or the `MaximumUnverifiedAge` cutoff. `auth.ErrUnauthenticated` or `auth.ErrForbidden` from it ends the session; any other error keeps the identity until `MaximumUnverifiedAge` since the last successful check, then ends it. A refresh never overwrites a change saved while it ran. A backend that fails the refresh's claim (its first write) gets a 500 without a provider call, unless reading the session back shows the claim committed.

- `password`: re-reads the user; a deleted user loses the session, and so does a session opened before the user's password hash or second factor changed ([Password](Password.md#gotchas)). Updates `Username` and `Email` only.
- `github`: refetches teams; outside every allowed team or token revoked ends the session; admin role follows `AdminTeams`.
- `oidc`: no refresher; roles and groups are fixed at login.

## Backends

- `MemoryBackend`: exactly one replica, lost on restart, non-production scale. Bounded by `MaximumSessions` (default 100000) and `MaximumBytes` of session IDs, keys and values (default 64 MiB; a replacement counts only what it adds): when full it drops expired entries, then evicts the entries expiring soonest, revocation markers included (an expiry-ordered heap: O(log n) per evicted entry, never a scan of every session); a single value larger than `MaximumBytes` is refused. It is not built for anonymous login floods: every login start stores a session, so a flood keeps it full and evicts real sessions; rate-limit the login routes or use Redis.
- `session/redisbackend`: any `redis.UniversalClient` (client, sentinel, cluster); you own and close the client; give it a `TLSConfig` when Redis is reached over a network you do not trust (the values are ciphertext, but the password and the commands are not; the forwardauth binary does this with `SESSION_REDIS_TLS_*` and reaches a Sentinel setup with `SESSION_REDIS_SENTINEL_*`, see [Forward-Auth Configuration](Forward-Auth-Configuration.md#session)); keys carry a hash tag, so `KeyPrefix` (default `session`) must not contain `{` or `}`. Logout and session rotation revoke on every replica; a revoked session never regains an identity and refuses writes while its revocation marker lives (Redis may evict it under its own eviction policy, as a full memory backend does). A value counts only while its session's index set lists it (the index lives at least as long as every value), because logout finds the values through the index: a session whose index Redis evicted reads as logged out, so its cookie can never outlive a logout. Run the session Redis with a `maxmemory-policy` of:
  - `noeviction` (recommended, ideally on a Redis of its own): nothing is ever dropped; when memory is full, writes that need memory fail, so logins and saves answer 500 until memory frees up.
  - `volatile-ttl`: every session key has a TTL, the shortest-lived go first (pending logins, one-minute retry receipts, sessions about to expire); an index outlives its values, so values go first. An evicted revocation marker lets the revoked session accept writes again, never an identity.
  - any `allkeys-*` or other `volatile-*` policy evicts arbitrary keys: users are logged out at random (an evicted value or index), logins fail (an evicted login state), revocation markers vanish as above; never a resurrected session, but unpredictable.

  Tested excerpt ([session/redisbackend/example_test.go](../../session/redisbackend/example_test.go)):

```go
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer func() { _ = client.Close() }() // nothing to flush

	backend, err := redisbackend.New(&redisbackend.Options{Client: client, KeyPrefix: "myapp:session"})
	if err != nil {
		fmt.Println(err)
		return
	}
	key, err := session.ParseKey("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		fmt.Println(err)
		return
	}
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: key})
```

- Own database: implement the five methods of [`session.Backend`](../../session/backend.go) (`Put`, `Get`, `Pop`, `CompareAndSwap`, `Revoke`) with their atomicity contracts. The built-in backends run the conformance suite [internal/backendtest](../../internal/backendtest/backendtest.go); it is internal to the module, so copy it into your tests.

## Gotchas

- Instances sharing `EncryptionKey`, Redis `KeyPrefix` and cookie name accept each other's sessions: give every application its own key and prefix.
- Plain `http` on a host other than `localhost`/loopback: browsers drop the `Secure` cookie and every login loops; set `InsecureCookie` for local development only.
- `SameSite: http.SameSiteStrictMode` is for password-only stores: the browser withholds it on the redirect back from the IdP, so `oidc.New` and `github.New` refuse such a store.
- No idle timeout: a session lives until logout, `MaximumAge` or a refusing refresh.

Source: [session/](../../session/) ([store.go](../../session/store.go), [guard.go](../../session/guard.go), [session.go](../../session/session.go), [memory.go](../../session/memory.go)), [session/redisbackend/backend.go](../../session/redisbackend/backend.go).
