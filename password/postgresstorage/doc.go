// Package postgresstorage implements password.Storage on PostgreSQL 18 with pgx/v5.
//
// Nothing runs DDL at startup: MigrationV1 holds the table for the application's own goose migrations.
// Every Storage contract is one statement; the compare-and-swap ones (UpdatePasswordHash, ConsumeTOTPAttempt,
// ConsumeTOTPStep, ConsumeBackupCode, SetTOTP) re-check their condition on the row a concurrent call left,
// which needs READ COMMITTED, PostgreSQL's default. Under REPEATABLE READ as the server or role default such a
// race fails with an error instead (never with a wrong result).
//
// The table govengers_auth_password_credentials holds the credentials only. The application's profile lives
// in its own table under the same user ID (auth.Identity.UserID), joined on it, for example
//
//	CREATE TABLE users (
//	    id           uuid PRIMARY KEY REFERENCES govengers_auth_password_credentials (user_id) ON DELETE CASCADE,
//	    display_name text NOT NULL
//	);
//
// when every user logs in with a password, created in the password provider's OnLogin hook (INSERT ... ON
// CONFLICT DO NOTHING). When users also come from OIDC or GitHub, drop the foreign key or point it the other
// way (credentials referencing users, created after the profile row). The library never deletes a user:
// delete the credentials row in your own statement.
//
// Every statement runs on Options.Pool, or on the caller's transaction through Storage.WithExecutor: create
// the credentials in the same commit as the profile row and the audit entry.
//
// The package never logs and never starts goroutines. Callers match on the password package's sentinels; a
// database error keeps pgx's error in its chain, so a caller maps it (errors.As with *pgconn.PgError: a
// serialization failure to retry, or the foreign key of the application's profile table); that chain is part
// of the API. Map on its Code and ConstraintName and never log or report its Detail: for a NOT NULL or CHECK
// violation PostgreSQL puts the whole failing row there, password hash and TOTP secret included. The Storage
// is safe for concurrent use; a WithExecutor view on a transaction or a connection is not.
package postgresstorage
