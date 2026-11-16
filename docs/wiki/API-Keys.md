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

`apikey/postgresstore` issues keys that belong to an owner (a user ID) and is their `Resolver`. Run `postgresstore.MigrationV1` and then `postgresstore.MigrationV2` in your goose migrations (table `govengers_auth_api_keys`; `owner_id` has no foreign key, add one to your users table, preferably `ON DELETE RESTRICT`: a cascade deletes the keys your audit log names).

```go
	store, err := postgresstore.New(&postgresstore.Options{
		Pool:   pool,
		Prefix: "todo",
		Load: func(_ context.Context, _ postgresstore.Executor, ownerID uuid.UUID) (*auth.Identity, error) {
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
- `Resolve` checks the shape before any query, reads the row by its primary key, compares the hash in constant time, refuses an expired or revoked key, then calls `Load(ctx, executor, ownerID)` on every request, so a deactivated or deleted owner (return an error matching `auth.ErrUnauthenticated`) loses every key at once. Refusals match `auth.ErrUnauthenticated` with a fixed `Reason` (`malformed key`, `unknown key`, `wrong secret`, `revoked key`, `expired key`); errors never contain the key.
- The key acts as its owner capped by its scopes: `Permissions` become what both the owner's permissions and the scopes grant (`*:write` and `tasks:read` give `tasks:read`; `tasks:write` and `*:read` give `tasks:read`), so a key never grants more than its owner has, also after the owner lost a permission. A key without the scope `*:write` drops the owner's `Roles`, `OIDCRoles`, `OIDCClientRoles`, `Groups` and `Teams`, which no resource scope can narrow: a read-only key of an admin is not an admin. `Provider` is `apikey`, `Subject` the key ID (the audit trail names the key), `UserID` the owner's, `Impersonator` nil.
- Scopes bind permission checks only. `UserID`, `Active`, `Attributes`, `Claims` and `Data` stay the owner's, so a key with the single scope `tasks:read` passes `IsAuthenticated`, `IsUser` and `HasUserID(owner)`. Put `HasPermission` on every route a key may reach, also where an ownership check alone would do (change my profile, delete my account), or keep keys off those routes.
- `LastUsedAt` is written at most once per `LastUsedInterval` (default 1 minute) per key: a busy key costs one write per interval. The write is part of the check: when it is due and fails (a read-only database during a failover), `Resolve` returns the error and the request is refused although the key is valid. Keys need a writable database, like logins.
- `Revoke(ctx, ownerID, id)` marks the key revoked and returns it with `revoked`, whether this call revoked it (`postgresstore.ErrKeyNotFound` when the owner has no such key; revoking again keeps the first `RevokedAt` and answers `revoked` false, so write the audit entry only when it is true); nothing is cached, so the next request with the key is refused on every replica. The row stays: your audit log names a key's calls by key ID (`Subject`), and `Get(ctx, id)` still leads from that ID to the owner. `List(ctx, ownerID)` returns the owner's keys without secrets, expired and revoked ones included (`ExpiresAt`, `RevokedAt`).
- `Purge(ctx, retention)` deletes keys revoked or expired more than `retention` ago and returns how many; run it from a scheduled job with a retention at least as long as your audit log's.
- Administrator view: `Get(ctx, id)`, `ListAll(ctx, after, limit)` (every owner's keys in ID order, pages of 1 to 1000, pass the last ID for the next page) and `RevokeAny(ctx, id)`. The store checks no caller: authorize these routes yourself (an admin check), like `Issue`, `List` and `Revoke` (the caller is the owner).
- In your transaction: `store.WithExecutor(tx)` returns a view whose every call runs on `tx` (a `pgx.Tx`, a pool, a connection, or livewire's `postgresadapter.TransactionFrom(ctx)`; nil is the pool), so a key is issued or revoked in the same commit as your audit entry, and a call inside a transaction never waits for a second pool connection. The view sees the transaction's uncommitted rows (an owner inserted before `Issue`) and its isolation; `Revoke` and `Resolve`'s last-use write need a read-write transaction. `Load` gets the view's executor: read the owner on it, so `Resolve` inside a transaction sees its rows and never waits for a second connection. A database error aborts the transaction. A view on a transaction or connection is not safe for concurrent use (pgx runs one statement at a time on it). Example: `ExampleStore_WithExecutor` in [example_test.go](../../apikey/postgresstore/example_test.go).
- Errors keep pgx's error: `errors.As(err, &postgresError)` with `*pgconn.PgError` reads the SQLSTATE (a serialization failure to retry). Map on `Code` and `ConstraintName`; never log or report `Detail`: for a NOT NULL or CHECK violation it holds the whole failing row, the key's secret hash included. An owner your foreign key refuses is `postgresstore.ErrOwnerNotFound` (map it to 400).
- `Issue` refuses a nil owner ID, an empty or over 200-byte name, a name with a NUL byte or invalid UTF-8, no or an invalid scope, and a past expiry with an `*auth.Error` of kind `auth.ErrInvalidRequest`; let only a session (not a key) reach your issue route, or a key could mint a wider one.

## Gotchas

- A route behind `apikey` refuses every bearer token that is not a key (an SPA's own token, a forward-auth JWT): do not combine it with `jwt.Verifier` on the same route.
- A `Resolver` identity without `Active` is refused by every check except `IsAuthenticated` (403).
- Static keys get only what you configure: `Roles: []string{auth.RoleAdmin}` for admin checks, permissions for `HasPermission`.

Source: [apikey/apikey.go](../../apikey/apikey.go).
