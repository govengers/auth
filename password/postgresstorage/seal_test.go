package postgresstorage_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/password"
	"github.com/govengers/auth/password/passwordtest"
	"github.com/govengers/auth/password/postgresstorage"
	"github.com/govengers/auth/seal"
)

const totpSecret = "JBSWY3DPEHPK3PXP"

var (
	oldKey = seal.Key{ID: "2026-01", Secret: bytes.Repeat([]byte("0123456789abcdef"), 2)}
	newKey = seal.Key{ID: "2026-11", Secret: bytes.Repeat([]byte("fedcba9876543210"), 2)}
)

func newSealer(t *testing.T, keys ...seal.Key) *seal.Sealer {
	t.Helper()
	sealer, err := seal.New(&seal.Options{Keys: keys})
	require.NoError(t, err)
	return sealer
}

func storageOn(t *testing.T, pool *pgxpool.Pool, sealer *seal.Sealer) *postgresstorage.Storage {
	t.Helper()
	storage, err := postgresstorage.New(&postgresstorage.Options{Pool: pool, Sealer: sealer})
	require.NoError(t, err)
	return storage
}

// storedSecret reads the column as it is at rest.
func storedSecret(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var secret string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT totp_secret FROM govengers_auth_password_credentials WHERE user_id = $1`, id).Scan(&secret))
	return secret
}

func createTOTPUser(t *testing.T, storage *postgresstorage.Storage, name string) uuid.UUID {
	t.Helper()
	secret := totpSecret
	user := &password.User{ID: uuid.New(), Username: &name, PasswordHash: "hash", TOTPEnabled: true, TOTPSecret: &secret}
	require.NoError(t, storage.CreateUser(t.Context(), user))
	return user.ID
}

func requireSecret(t *testing.T, storage *postgresstorage.Storage, id uuid.UUID) {
	t.Helper()
	user, err := storage.GetUserByID(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, totpSecret, *user.TOTPSecret)
}

func TestSealedStorageConformance(t *testing.T) {
	sealer := newSealer(t, newKey)
	passwordtest.Run(t, func(t *testing.T) password.Storage {
		return storageOn(t, postgres.Pool(t), sealer)
	})
}

// CreateUser and SetTOTP store the secret sealed only; reads answer the plaintext.
func TestSealerSealsTheSecretAtRest(t *testing.T) {
	pool := postgres.Pool(t)
	storage := storageOn(t, pool, newSealer(t, newKey))
	created := createTOTPUser(t, storage, "ada")
	username := "grace"
	enrolled := &password.User{ID: uuid.New(), Username: &username, PasswordHash: "hash"}
	require.NoError(t, storage.CreateUser(t.Context(), enrolled))
	set, err := storage.SetTOTP(t.Context(), enrolled.ID, totpSecret, []string{"code-hash"})
	require.NoError(t, err)
	require.True(t, set)

	for _, id := range []uuid.UUID{created, enrolled.ID} {
		atRest := storedSecret(t, pool, id)
		require.True(t, strings.HasPrefix(atRest, "v1.2026-11."), atRest)
		require.NotContains(t, atRest, totpSecret)
		requireSecret(t, storage, id)
	}
}

// Rows written before the Sealer was set keep working, and ResealTOTPSecrets seals them; after a key
// rotation it moves every secret to the new primary key, so the old key can leave the ring.
func TestResealTOTPSecrets(t *testing.T) {
	pool := postgres.Pool(t)
	plain := storageOn(t, pool, nil)
	legacy := createTOTPUser(t, plain, "legacy")
	nilUser := "nil-id"
	secret := totpSecret
	require.NoError(t, plain.CreateUser(t.Context(), &password.User{ID: uuid.Nil, Username: &nilUser, PasswordHash: "hash", TOTPEnabled: true, TOTPSecret: &secret}))
	// more rows than one page of the reseal
	_, err := pool.Exec(t.Context(), `
INSERT INTO govengers_auth_password_credentials (user_id, username, password_hash, totp_enabled, totp_secret)
SELECT gen_random_uuid(), 'user-' || n, 'hash', true, $1 FROM generate_series(1, 150) AS n`, totpSecret)
	require.NoError(t, err)
	sealedOld := storageOn(t, pool, newSealer(t, oldKey))
	requireSecret(t, sealedOld, legacy)
	sealedEarlier := createTOTPUser(t, sealedOld, "sealed-earlier")

	changed, err := sealedOld.ResealTOTPSecrets(t.Context())
	require.NoError(t, err)
	require.Equal(t, 152, changed, "every plaintext row, the nil user ID included; the sealed one stays")
	require.True(t, strings.HasPrefix(storedSecret(t, pool, legacy), "v1.2026-01."))
	requireSecret(t, sealedOld, legacy)
	changed, err = sealedOld.ResealTOTPSecrets(t.Context())
	require.NoError(t, err)
	require.Zero(t, changed, "nothing left to do")

	rotated := storageOn(t, pool, newSealer(t, newKey, oldKey))
	changed, err = rotated.ResealTOTPSecrets(t.Context())
	require.NoError(t, err)
	require.Equal(t, 153, changed)
	newOnly := storageOn(t, pool, newSealer(t, newKey))
	for _, id := range []uuid.UUID{legacy, sealedEarlier, uuid.Nil} {
		require.True(t, strings.HasPrefix(storedSecret(t, pool, id), "v1.2026-11."))
		requireSecret(t, newOnly, id)
	}
	var unsealed int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM govengers_auth_password_credentials WHERE totp_secret NOT LIKE 'v1.2026-11.%'`).Scan(&unsealed))
	require.Zero(t, unsealed)
}

// A sealed secret copied into another user's row does not open there, and the reseal stops at it.
func TestSealedSecretIsBoundToItsRow(t *testing.T) {
	pool := postgres.Pool(t)
	storage := storageOn(t, pool, newSealer(t, newKey))
	victim := createTOTPUser(t, storage, "victim")
	attacker := createTOTPUser(t, storage, "attacker")
	_, err := pool.Exec(t.Context(), `UPDATE govengers_auth_password_credentials SET totp_secret = $2 WHERE user_id = $1`, attacker, storedSecret(t, pool, victim))
	require.NoError(t, err)

	_, err = storage.GetUserByID(t.Context(), attacker)
	require.ErrorIs(t, err, seal.ErrInvalid)
	require.ErrorContains(t, err, attacker.String())
	require.NotContains(t, err.Error(), totpSecret)
	_, err = storage.ResealTOTPSecrets(t.Context())
	require.ErrorIs(t, err, seal.ErrInvalid)
}

func TestSealedSecretWithoutASealer(t *testing.T) {
	pool := postgres.Pool(t)
	id := createTOTPUser(t, storageOn(t, pool, newSealer(t, newKey)), "ada")
	plain := storageOn(t, pool, nil)

	_, err := plain.GetUserByID(t.Context(), id)
	require.ErrorContains(t, err, "sealed but Options.Sealer is not set")
	_, err = plain.ResealTOTPSecrets(t.Context())
	require.ErrorContains(t, err, "Options.Sealer is not set")
}
