package postgresstore

// MigrationV1 creates govengers_auth_api_keys, one row per issued key. Run it from one of the application's
// goose migrations, in the schema the store's pool uses:
//
//	-- +goose Up
//	-- the content of postgresstore.MigrationV1
//
// or from a goose Go migration with tx.ExecContext(ctx, postgresstore.MigrationV1). Later versions of the
// module add MigrationV2 and so on; never edit an applied migration. It runs inside the migration's
// transaction (SET LOCAL) and passes squawk.
//
// owner_id has no foreign key: add one to your users table in your own migration (ON DELETE CASCADE ends a
// deleted user's keys with the user).
const MigrationV1 = `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE TABLE govengers_auth_api_keys (
    id           uuid PRIMARY KEY,
    owner_id     uuid NOT NULL,
    name         text NOT NULL CHECK (name <> ''),
    secret_hash  bytea NOT NULL CHECK (length(secret_hash) = 32),
    scopes       text[] NOT NULL CHECK (cardinality(scopes) > 0),
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz,
    last_used_at timestamptz
);

CREATE INDEX govengers_auth_api_keys_owner ON govengers_auth_api_keys (owner_id, created_at);
`
