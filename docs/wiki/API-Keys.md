# API keys

`apikey.Authenticator` turns a presented API key into an `auth.Identity`: static keys from configuration (name, secret, roles, permissions) and keys your application issues, looked up by a `Resolver`. Works with any provider and in front of the `session.Guard`.

## Wiring

Tested ([apikey/example_test.go](../../apikey/example_test.go)):

```go
	authenticator, err := apikey.New(&apikey.Options{
		Keys: []apikey.Key{{
			Name:        "ci",
			Secret:      "ci-secret-0123456789",
			Roles:       []string{auth.RoleAdmin},
			Permissions: []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}},
		}},
	})
```

Mount it before the Guard: `authenticator.Middleware()(guard.RequireAPI()(handler))`, on gin `ginadapter.Middleware(authenticator.Middleware())` before `ginadapter.Middleware(guard.RequireAPI())`. The Guard passes a request that already carries an identity; requests without a key fall through to the session.

## Behaviour

- Keys come from `X-API-Key` (`HeaderName`; not `Authorization`) or `Authorization: Bearer <key>` (scheme in any case).
- No key: passes through untouched. A wrong key: 401 `invalid_api_key`, never a fall-through, also when a valid session cookie is present.
- Static key identity: `Provider` `apikey`, `Subject` and `Username` the key name, the key's `Roles` and `Permissions`, `Active` true.
- Secrets: at least 16 bytes, no surrounding whitespace, names and secrets unique; compared as SHA-256 in constant time.
- `Resolver func(ctx, key) (*auth.Identity, error)` for keys you issue: return an error matching `auth.ErrUnauthenticated` for unknown or revoked keys (any other error is 500, its chain dropped; only `context.Canceled` and `context.DeadlineExceeded` stay detectable); set `Active: true` yourself; put the key's access level into `Permissions` (e.g. a stored `read_only` level becomes `*:read`); never repeat the key in an error text: it is reported in `Outcome.Err` and recorded on the wide event.

## Gotchas

- A route behind `apikey` refuses every bearer token that is not a key (an SPA's own token, a forward-auth JWT): do not combine it with `jwt.Verifier` on the same route.
- A `Resolver` identity without `Active` is refused by every check except `IsAuthenticated` (403).
- Static keys get only what you configure: `Roles: []string{auth.RoleAdmin}` for admin checks, permissions for `HasPermission`.

Source: [apikey/apikey.go](../../apikey/apikey.go).
