package postgresstorage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/postgrestest"
	"github.com/govengers/auth/password"
	"github.com/govengers/auth/password/passwordtest"
	"github.com/govengers/auth/password/postgresstorage"
)

func TestMain(m *testing.M) { postgrestest.Main(m) }

func newStorage(t *testing.T) *postgresstorage.Storage {
	t.Helper()
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: postgrestest.New(t, postgresstorage.MigrationV1)})
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
	pool := postgrestest.New(t, postgresstorage.MigrationV1,
		`ALTER TABLE govengers_auth_password_credentials ADD COLUMN locale text NOT NULL DEFAULT 'en'`)
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: pool})
	require.NoError(t, err)
	username := "ada"
	user := &password.User{ID: uuid.New(), Username: &username, PasswordHash: "hash"}

	require.NoError(t, storage.CreateUser(t.Context(), user))
	read, err := storage.GetUserByUsername(t.Context(), "ada")
	require.NoError(t, err)
	require.Equal(t, user, read)
}

func TestCreateUserRefusesAUserWithoutUsernameAndEmail(t *testing.T) {
	storage := newStorage(t)

	err := storage.CreateUser(t.Context(), &password.User{ID: uuid.New(), PasswordHash: "hash"})

	require.ErrorContains(t, err, "postgres password storage: create user")
	require.NotErrorIs(t, err, password.ErrUserExists)
}

func TestErrorsAreReportedWithoutTheirChain(t *testing.T) {
	pool := postgrestest.New(t, postgresstorage.MigrationV1)
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: pool})
	require.NoError(t, err)
	pool.Close()
	ctx := context.Background()
	id := uuid.New()

	_, err = storage.GetUserByID(ctx, id)
	require.ErrorContains(t, err, "postgres password storage: read user")
	_, err = storage.ConsumeTOTPAttempt(ctx, id, 5)
	require.ErrorContains(t, err, "postgres password storage: consume TOTP attempt")
	_, err = storage.ConsumeTOTPStep(ctx, id, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	require.ErrorContains(t, err, "postgres password storage: consume TOTP step")
	require.ErrorContains(t, storage.ClearTOTP(ctx, id), "postgres password storage: clear TOTP")
}
