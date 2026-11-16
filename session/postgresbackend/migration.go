package postgresbackend

// MigrationV1 creates the session tables. Run it from one of the application's goose migrations, in
// the schema the backend's pool uses:
//
//	-- +goose Up
//	-- the content of postgresbackend.MigrationV1
//
// or from a goose Go migration with tx.ExecContext(ctx, postgresbackend.MigrationV1). Later versions
// of the module add MigrationV2 and so on; never edit an applied migration. It runs inside the
// migration's transaction (SET LOCAL) and passes squawk.
//
// govengers_auth_sessions holds one row per session ID: when the last of its values expires and the
// revocation marker. govengers_auth_session_values holds the encrypted values; they go with their
// session row.
const MigrationV1 = `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE TABLE govengers_auth_sessions (
    session_id    text PRIMARY KEY CHECK (session_id <> ''),
    expires_at    timestamptz NOT NULL,
    revoked_until timestamptz
);

CREATE INDEX govengers_auth_sessions_expiry ON govengers_auth_sessions (expires_at);

CREATE TABLE govengers_auth_session_values (
    session_id text NOT NULL REFERENCES govengers_auth_sessions (session_id) ON DELETE CASCADE,
    key        text NOT NULL,
    value      bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (session_id, key)
);

CREATE INDEX govengers_auth_session_values_expiry ON govengers_auth_session_values (expires_at);
`
