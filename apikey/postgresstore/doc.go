// Package postgresstore issues per-owner API keys and keeps them in PostgreSQL 18 (pgx/v5); its
// Store.Resolve is the apikey.Resolver that turns a presented key into the owner's identity, capped by the
// key's scopes.
//
// A key is "<prefix>_<id>.<secret>", shown once at Issue. The table holds the SHA-256 of the 32 random
// secret bytes, never the secret: a key of that entropy needs no slow hash, and one indexed lookup by id
// plus a constant-time comparison is all a request costs. Revoke marks the row revoked, so the next request
// with the key is refused on every replica; nothing is cached. The row stays, so the key ID an audit entry
// names as actor still leads to its owner (Get), until Purge deletes it after the application's retention.
//
// Every statement runs on Options.Pool, or on the caller's transaction through Store.WithExecutor: a key is
// issued or revoked in the same commit as the application's own rows and audit entry.
//
// Nothing runs DDL at startup: MigrationV1 and MigrationV2 hold the table for the application's own goose
// migrations. The package never logs and never starts goroutines. A database error keeps pgx's error in its
// chain, so a caller maps it (errors.As with *pgconn.PgError: a serialization failure to retry, for example);
// that chain is part of the API. The Store is safe for concurrent use.
package postgresstore
