// Package postgresstore issues per-owner API keys and keeps them in PostgreSQL 18 (pgx/v5); its
// Store.Resolve is the apikey.Resolver that turns a presented key into the owner's identity, capped by the
// key's scopes.
//
// A key is "<prefix>_<id>.<secret>", shown once at Issue. The table holds the SHA-256 of the 32 random
// secret bytes, never the secret: a key of that entropy needs no slow hash, and one indexed lookup by id
// plus a constant-time comparison is all a request costs. Revoke deletes the row, so the next request with
// the key is refused on every replica; nothing is cached.
//
// Nothing runs DDL at startup: MigrationV1 holds the table for the application's own goose migrations.
// The package never logs and never starts goroutines. Errors of pgx are reported by message only. The Store
// is safe for concurrent use.
package postgresstore
