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
// owner_id has no foreign key: add one to your users table in your own migration; Issue answers an owner it
// refuses with ErrOwnerNotFound. Prefer ON DELETE RESTRICT (deactivate users instead of deleting them):
// ON DELETE CASCADE deletes a deleted user's keys with the user, and audit entries naming those keys no longer
// lead to an owner. Run MigrationV2 after it.
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

// MigrationV2 adds revoked_at to govengers_auth_api_keys: Revoke marks a key instead of deleting it, so the key
// ID an audit entry names still leads to its owner; Purge deletes ended keys after a retention. Run it in a
// goose migration after MigrationV1, the same way. Adding a nullable column without a default rewrites
// nothing.
const MigrationV2 = `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

ALTER TABLE govengers_auth_api_keys ADD COLUMN revoked_at timestamptz;
`
