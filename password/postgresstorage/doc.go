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
// The package never logs and never starts goroutines. Errors of pgx are reported by message only; callers
// match on the password package's sentinels. The Storage is safe for concurrent use.
package postgresstorage
