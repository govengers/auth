// Package postgresbackend implements session.Backend on PostgreSQL 18 with pgx/v5, so that sessions work
// across replicas without Redis.
//
// Nothing runs DDL at startup: MigrationV1 holds the tables for the application's own goose migrations.
// Values live in govengers_auth_session_values under a row per session in govengers_auth_sessions, whose
// lock serializes Put against Revoke. Expired rows never count, and Sweep deletes them; the application
// schedules it.
//
// Single-statement operations rely on READ COMMITTED, PostgreSQL's default: under REPEATABLE READ as the
// server or role default, a Put, Pop or CompareAndSwap racing another write of the same row fails with an
// error instead of waiting for it (never with a wrong result). Revoke pins READ COMMITTED itself.
//
// The package never logs and never starts goroutines. Errors of pgx are reported by message only;
// callers cannot match on them. The Backend is safe for concurrent use.
package postgresbackend
