package postgresstorage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/govengers/postgrestest"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/govengers/auth/password"
	"github.com/govengers/auth/password/passwordtest"
	"github.com/govengers/auth/password/postgresstorage"
)

// postgres gives every test a database of its own with MigrationV1 applied.
var postgres = postgrestest.New(&postgrestest.Options{
	Migrate:     postgrestest.Statements(postgresstorage.MigrationV1),
	Fingerprint: postgresstorage.MigrationV1,
})

func TestMain(m *testing.M) { goleak.VerifyTestMain(postgres.Main(m)) }

func newStorage(t *testing.T) *postgresstorage.Storage {
	t.Helper()
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: postgres.Pool(t)})
	require.NoError(t, err)
	return storage
}

func TestStorageConformance(t *testing.T) {
	passwordtest.Run(t, func(t *testing.T) password.Storage { return newStorage(t) })
}

func TestNew(t *testing.T) {
	_, err := postgresstorage.New(nil)
	require.ErrorContains(t, err, "Pool is required")
	_, err = postgresstorage.New(&postgresstorage.Options{})
	require.ErrorContains(t, err, "Pool is required")
}

// An application adds its own columns to the credentials table; the storage keeps working.
func TestApplicationColumnsDoNotBreakTheStorage(t *testing.T) {
	pool := postgres.Pool(t)
	_, err := pool.Exec(t.Context(), `ALTER TABLE govengers_auth_password_credentials ADD COLUMN locale text NOT NULL DEFAULT 'en'`)
	require.NoError(t, err)
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: pool})
	require.NoError(t, err)
	username := "ada"
	user := &password.User{ID: uuid.New(), Username: &username, PasswordHash: "hash"}

	require.NoError(t, storage.CreateUser(t.Context(), user))
	read, err := storage.GetUserByUsername(t.Context(), "ada")
	require.NoError(t, err)
	require.Equal(t, user, read)
}

// Case folding is ASCII on every database: under a Turkish collation lower('I') is a dotless i, which would
// make ADMIN and admin two users. The columns stand in for a database whose default collation is Turkish.
func TestCaseFoldingIgnoresTheCollation(t *testing.T) {
	pool := postgres.Pool(t)
	_, err := pool.Exec(t.Context(), `
ALTER TABLE govengers_auth_password_credentials
    ALTER COLUMN username TYPE text COLLATE "tr-x-icu", ALTER COLUMN email TYPE text COLLATE "tr-x-icu"`)
	require.NoError(t, err)
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: pool})
	require.NoError(t, err)
	username, email := "ADMIN", "ADMIN@EXAMPLE.COM"
	require.NoError(t, storage.CreateUser(t.Context(), &password.User{ID: uuid.New(), Username: &username, Email: &email, PasswordHash: "hash"}))

	_, err = storage.GetUserByUsername(t.Context(), "admin")
	require.NoError(t, err)
	_, err = storage.GetUserByEmail(t.Context(), "admin@example.com")
	require.NoError(t, err)
	lower := "admin"
	require.ErrorIs(t, storage.CreateUser(t.Context(), &password.User{ID: uuid.New(), Username: &lower, PasswordHash: "hash"}), password.ErrUserExists)
}

// The provider filters NUL bytes itself; application code calling the lookups directly gets the same answer.
func TestLookupOfAnIdentifierTextCannotHoldFindsNobody(t *testing.T) {
	storage := newStorage(t)
	for _, identifier := range []string{"ad\x00a", "ad\x00a@example.com", "caf\xff", "caf\xff@example.com"} {
		_, err := storage.GetUserByUsername(t.Context(), identifier)
		require.ErrorIs(t, err, password.ErrUserNotFound, "username %q", identifier)
		_, err = storage.GetUserByEmail(t.Context(), identifier)
		require.ErrorIs(t, err, password.ErrUserNotFound, "email %q", identifier)
	}
}

func TestCreateUserRefusesAUserWithoutUsernameAndEmail(t *testing.T) {
	storage := newStorage(t)

	err := storage.CreateUser(t.Context(), &password.User{ID: uuid.New(), PasswordHash: "hash"})

	require.ErrorContains(t, err, "postgres password storage: create user")
	require.NotErrorIs(t, err, password.ErrUserExists)
	var postgresError *pgconn.PgError
	require.ErrorAs(t, err, &postgresError)
	require.Equal(t, "23514", postgresError.Code, "the table's CHECK")
}

// requirePostgresError asserts that err names operation and keeps PostgreSQL's error with code.
func requirePostgresError(t *testing.T, err error, operation, code string) {
	t.Helper()
	require.ErrorContains(t, err, "postgres password storage: "+operation)
	var postgresError *pgconn.PgError
	require.ErrorAs(t, err, &postgresError)
	require.Equal(t, code, postgresError.Code)
}

// A database error keeps pgx's error in its chain (part of the API), so the application maps it.
func TestErrorsKeepThePostgreSQLError(t *testing.T) {
	pool := postgres.Pool(t)
	storage := storageOn(t, pool, newSealer(t, newKey))
	_, err := pool.Exec(t.Context(), `DROP TABLE govengers_auth_password_credentials`)
	require.NoError(t, err)
	ctx := t.Context()
	id := uuid.New()
	username := "ada"

	requirePostgresError(t, storage.CreateUser(ctx, &password.User{ID: id, Username: &username, PasswordHash: "hash"}), "create user", "42P01")
	_, err = storage.GetUserByID(ctx, id)
	requirePostgresError(t, err, "read user", "42P01")
	_, err = storage.ConsumeTOTPAttempt(ctx, id, 5)
	requirePostgresError(t, err, "consume TOTP attempt", "42P01")
	_, err = storage.ConsumeTOTPStep(ctx, id, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	requirePostgresError(t, err, "consume TOTP step", "42P01")
	requirePostgresError(t, storage.ClearTOTP(ctx, id), "clear TOTP", "42P01")
	_, err = storage.ResealTOTPSecrets(ctx)
	requirePostgresError(t, err, "reseal TOTP secrets: read", "42P01")
}

// The application's profile table referenced by the credentials: a missing profile is the foreign key's
// error, kept in the chain.
func TestCreateUserKeepsTheForeignKeyError(t *testing.T) {
	pool := postgres.Pool(t)
	for _, statement := range []string{
		`CREATE TABLE users (id uuid PRIMARY KEY)`,
		`ALTER TABLE govengers_auth_password_credentials ADD FOREIGN KEY (user_id) REFERENCES users (id)`,
	} {
		_, err := pool.Exec(t.Context(), statement)
		require.NoError(t, err)
	}
	username := "ada"

	err := storageOn(t, pool, nil).CreateUser(t.Context(), &password.User{ID: uuid.New(), Username: &username, PasswordHash: "hash"})

	requirePostgresError(t, err, "create user", "23503")
}

// singleConnectionPool is a pool that holds at most one connection: a statement that does not run on the
// transaction holding it waits for the context's deadline.
func singleConnectionPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	configuration, err := pgxpool.ParseConfig(postgres.Database(t))
	require.NoError(t, err)
	configuration.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), configuration)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// Every method of a WithExecutor view runs on the caller's transaction: on a pool of one connection, which the
// transaction holds, none waits for a second, and a rollback takes the user with it.
func TestWithExecutorRunsEveryCallOnTheTransaction(t *testing.T) {
	pool := singleConnectionPool(t)
	storage := storageOn(t, pool, newSealer(t, newKey))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	transaction, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = transaction.Rollback(context.Background()) }) // a no-op after the explicit rollback
	view := storage.WithExecutor(transaction)
	username, email := "ada", "ada@example.com"
	id := uuid.New()

	require.NoError(t, view.CreateUser(ctx, &password.User{ID: id, Username: &username, Email: &email, PasswordHash: "old"}))
	require.ErrorIs(t, view.CreateUser(ctx, &password.User{ID: uuid.New(), Username: &username, PasswordHash: "hash"}), password.ErrUserExists)
	_, err = view.GetUserByUsername(ctx, username)
	require.NoError(t, err, "the transaction is still usable after ErrUserExists")
	_, err = view.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.NoError(t, view.UpdatePasswordHash(ctx, id, "old", "new"))
	remaining, err := view.ConsumeTOTPAttempt(ctx, id, 5)
	require.NoError(t, err)
	require.Equal(t, 4, remaining)
	require.NoError(t, view.ResetTOTPAttempts(ctx, id))
	set, err := view.SetTOTP(ctx, id, totpSecret, []string{"code"})
	require.NoError(t, err)
	require.True(t, set)
	consumed, err := view.ConsumeTOTPStep(ctx, id, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.True(t, consumed)
	consumed, err = view.ConsumeBackupCode(ctx, id, "code")
	require.NoError(t, err)
	require.True(t, consumed)
	changed, err := view.ResealTOTPSecrets(ctx)
	require.NoError(t, err)
	require.Zero(t, changed, "sealed with the primary key already")
	require.NoError(t, view.ClearTOTP(ctx, id))
	require.ErrorIs(t, view.ResetTOTPAttempts(ctx, uuid.New()), password.ErrUserNotFound, "the user lookup runs on the transaction too")
	user, err := view.GetUserByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "new", user.PasswordHash)
	require.NoError(t, transaction.Rollback(ctx))

	_, err = storage.GetUserByID(ctx, id)
	require.ErrorIs(t, err, password.ErrUserNotFound, "the user rolled back with the transaction")
	_, err = storage.WithExecutor(nil).GetUserByID(ctx, id)
	require.ErrorIs(t, err, password.ErrUserNotFound, "a nil executor is the pool")
}

// Credentials and the application's profile row commit together.
func TestCreateUserCommitsWithTheApplicationsRows(t *testing.T) {
	pool := postgres.Pool(t)
	_, err := pool.Exec(t.Context(), `CREATE TABLE users (id uuid PRIMARY KEY REFERENCES govengers_auth_password_credentials (user_id))`)
	require.NoError(t, err)
	storage := storageOn(t, pool, nil)
	username := "ada"
	id := uuid.New()
	transaction, err := pool.Begin(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = transaction.Rollback(context.Background()) }) // a no-op after the commit

	require.NoError(t, storage.WithExecutor(transaction).CreateUser(t.Context(), &password.User{ID: id, Username: &username, PasswordHash: "hash"}))
	_, err = transaction.Exec(t.Context(), `INSERT INTO users (id) VALUES ($1)`, id)
	require.NoError(t, err, "the profile's foreign key sees the uncommitted credentials")
	_, err = storage.GetUserByID(t.Context(), id)
	require.ErrorIs(t, err, password.ErrUserNotFound, "not visible before the commit")
	require.NoError(t, transaction.Commit(t.Context()))

	_, err = storage.GetUserByID(t.Context(), id)
	require.NoError(t, err)
}
