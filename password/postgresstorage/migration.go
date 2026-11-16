package postgresstorage

// MigrationV1 creates govengers_auth_password_credentials, one row per password user. Run it from one of
// the application's goose migrations, in the schema the storage's pool uses:
//
//	-- +goose Up
//	-- the content of postgresstorage.MigrationV1
//
// or from a goose Go migration with tx.ExecContext(ctx, postgresstorage.MigrationV1). Later versions of
// the module add MigrationV2 and so on; never edit an applied migration. It runs inside the migration's
// transaction (SET LOCAL) and passes squawk.
//
// The table holds credentials only, keyed by user_id, the password.User ID and auth.Identity.UserID. Keep
// the profile (display name, roles, settings) in your own table with the same ID and join on it; the
// foreign key direction is yours (see the package documentation). The storage names every column it
// reads and writes, so columns your own migrations add (nullable or with a default) do not break it.
const MigrationV1 = `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE TABLE govengers_auth_password_credentials (
    user_id            uuid PRIMARY KEY,
    username           text CHECK (username <> ''),
    email              text CHECK (email <> ''),
    password_hash      text NOT NULL,
    totp_enabled       boolean NOT NULL DEFAULT false,
    totp_secret        text,
    backup_code_hashes text[] NOT NULL DEFAULT '{}',
    -- the attempt counter stays far below the int range
    -- squawk-ignore prefer-bigint-over-int
    totp_attempts      integer NOT NULL DEFAULT 0 CHECK (totp_attempts >= 0),
    totp_step          timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CHECK (username IS NOT NULL OR email IS NOT NULL)
);

-- COLLATE "C": lower() folds ASCII only, whatever the database's default collation (a Turkish one folds
-- "I" to a dotless i); registration allows ASCII usernames and emails only.
CREATE UNIQUE INDEX govengers_auth_password_credentials_username
    ON govengers_auth_password_credentials (lower(username COLLATE "C"));
CREATE UNIQUE INDEX govengers_auth_password_credentials_email
    ON govengers_auth_password_credentials (lower(email COLLATE "C"));
`
