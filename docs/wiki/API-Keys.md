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

## Per-user keys on PostgreSQL

`apikey/postgresstore` issues keys that belong to an owner (a user ID) and is their `Resolver`. Run `postgresstore.MigrationV1` in one of your goose migrations (table `govengers_auth_api_keys`; `owner_id` has no foreign key, add one to your users table).

```go
	store, err := postgresstore.New(&postgresstore.Options{
		Pool:   pool,
		Prefix: "todo",
		Load: func(_ context.Context, ownerID uuid.UUID) (*auth.Identity, error) {
			// look the user up in your own table; a deleted one is &auth.Error{Kind: auth.ErrUnauthenticated}
			return &auth.Identity{UserID: ownerID, Active: true, Permissions: []auth.Permission{{Resource: auth.AllResources, Access: auth.AccessWrite}}}, nil
		},
	})
	if err != nil {
		return
	}
	text, key, err := store.Issue(ctx, uuid.New(), postgresstore.IssueRequest{
		Name:   "ci",
		Scopes: []auth.Permission{{Resource: "tasks", Access: auth.AccessRead}},
	})
	if err != nil {
		return
	}
	fmt.Println("show once:", text, "id:", key.ID)

	authenticator, err := apikey.New(&apikey.Options{Resolver: store.Resolve})
```

Tested in [apikey/postgresstore/example_test.go](../../apikey/postgresstore/example_test.go); a full server with key routes is [examples/postgres](../../examples/postgres/main.go).

- Key text: `<Prefix>_<id>.<secret>`, `id` the key's UUIDv7 as 32 lower-case hex characters, `secret` 32 random bytes in base64url (43 characters). `Prefix` is required (a lower-case letter, then 1 to 15 lower-case letters or digits) so secret scanners and people recognize a leaked key. `Issue` returns the text once; the table holds the SHA-256 of the secret only (a 256-bit random secret needs no slow hash).
- `Resolve` checks the shape before any query, reads the row by its primary key, compares the hash in constant time, refuses an expired key, then calls `Load(ctx, ownerID)` on every request, so a deactivated or deleted owner (return an error matching `auth.ErrUnauthenticated`) loses every key at once. Refusals match `auth.ErrUnauthenticated` with a fixed `Reason` (`malformed key`, `unknown key`, `wrong secret`, `expired key`); errors never contain the key.
- The key acts as its owner capped by its scopes: `Permissions` become what both the owner's permissions and the scopes grant (`*:write` and `tasks:read` give `tasks:read`; `tasks:write` and `*:read` give `tasks:read`), so a key never grants more than its owner has, also after the owner lost a permission. A key without the scope `*:write` drops the owner's `Roles`, `OIDCRoles`, `OIDCClientRoles`, `Groups` and `Teams`, which no resource scope can narrow: a read-only key of an admin is not an admin. `Provider` is `apikey`, `Subject` the key ID (the audit trail names the key), `UserID` the owner's, `Impersonator` nil.
- Scopes bind permission checks only. `UserID`, `Active`, `Attributes`, `Claims` and `Data` stay the owner's, so a key with the single scope `tasks:read` passes `IsAuthenticated`, `IsUser` and `HasUserID(owner)`. Put `HasPermission` on every route a key may reach, also where an ownership check alone would do (change my profile, delete my account), or keep keys off those routes.
- `LastUsedAt` is written at most once per `LastUsedInterval` (default 1 minute) per key: a busy key costs one write per interval. The write is part of the check: when it is due and fails (a read-only database during a failover), `Resolve` returns the error and the request is refused although the key is valid. Keys need a writable database, like logins.
- `Revoke(ctx, ownerID, id)` deletes the row (`postgresstore.ErrKeyNotFound` when the owner has no such key); nothing is cached, so the next request with the key is refused on every replica. `List(ctx, ownerID)` returns the owner's keys without secrets, expired ones included.
- `Issue` refuses a nil owner ID, an empty or over 200-byte name, a name with a NUL byte or invalid UTF-8, no or an invalid scope, and a past expiry with an `*auth.Error` of kind `auth.ErrInvalidRequest`; let only a session (not a key) reach your issue route, or a key could mint a wider one.

## Gotchas

- A route behind `apikey` refuses every bearer token that is not a key (an SPA's own token, a forward-auth JWT): do not combine it with `jwt.Verifier` on the same route.
- A `Resolver` identity without `Active` is refused by every check except `IsAuthenticated` (403).
- Static keys get only what you configure: `Roles: []string{auth.RoleAdmin}` for admin checks, permissions for `HasPermission`.

Source: [apikey/apikey.go](../../apikey/apikey.go).
