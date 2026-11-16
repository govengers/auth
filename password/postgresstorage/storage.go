package postgresstorage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/password"
	"github.com/govengers/auth/seal"
)

// uniqueViolation is the SQLSTATE of a duplicate user ID, username or email.
const uniqueViolation = "23505"

const insertUser = `
INSERT INTO govengers_auth_password_credentials
    (user_id, username, email, password_hash, totp_enabled, totp_secret, backup_code_hashes)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

const selectUser = `
SELECT user_id, username, email, password_hash, totp_enabled, totp_secret, backup_code_hashes
FROM govengers_auth_password_credentials `

const (
	// COLLATE "C" folds ASCII only, on every database whatever its default collation, as the indexes do.
	selectUserByUsername = selectUser + `WHERE lower(username COLLATE "C") = lower($1 COLLATE "C")`
	selectUserByEmail    = selectUser + `WHERE lower(email COLLATE "C") = lower($1 COLLATE "C")`
	selectUserByID       = selectUser + `WHERE user_id = $1`
)

const userExists = `SELECT EXISTS (SELECT 1 FROM govengers_auth_password_credentials WHERE user_id = $1)`

//nolint:gosec // G101: SQL naming the password_hash column, no credential
const updatePasswordHash = `
UPDATE govengers_auth_password_credentials SET password_hash = $3 WHERE user_id = $1 AND password_hash = $2`

// consumeTOTPAttempt reserves an attempt below the maximum; a concurrent call re-checks the counter on the row
// it waited for.
const consumeTOTPAttempt = `
UPDATE govengers_auth_password_credentials SET totp_attempts = totp_attempts + 1
WHERE user_id = $1 AND totp_attempts < $2
RETURNING $2 - totp_attempts`

const resetTOTPAttempts = `UPDATE govengers_auth_password_credentials SET totp_attempts = 0 WHERE user_id = $1`

const consumeTOTPStep = `
UPDATE govengers_auth_password_credentials SET totp_step = $2
WHERE user_id = $1 AND (totp_step IS NULL OR totp_step < $2)`

const consumeBackupCode = `
UPDATE govengers_auth_password_credentials SET backup_code_hashes = array_remove(backup_code_hashes, $2)
WHERE user_id = $1 AND $2 = ANY (backup_code_hashes)`

const setTOTP = `
UPDATE govengers_auth_password_credentials
SET totp_enabled = true, totp_secret = $2, backup_code_hashes = $3, totp_attempts = 0
WHERE user_id = $1 AND NOT totp_enabled`

// selectTOTPSecrets pages through the stored TOTP secrets in user ID order, after $1 (NULL: from the start,
// so a user with the nil UUID is not skipped).
//
//nolint:gosec // G101: SQL naming the totp_secret column, no credential
const selectTOTPSecrets = `
SELECT user_id, totp_secret FROM govengers_auth_password_credentials
WHERE totp_secret IS NOT NULL AND ($1::uuid IS NULL OR user_id > $1)
ORDER BY user_id
LIMIT $2`

// replaceTOTPSecret swaps a TOTP secret while it is still the one read, so a concurrent change of TOTP wins.
//
//nolint:gosec // G101: SQL naming the totp_secret column, no credential
const replaceTOTPSecret = `
UPDATE govengers_auth_password_credentials SET totp_secret = $3 WHERE user_id = $1 AND totp_secret = $2`

const clearTOTP = `
UPDATE govengers_auth_password_credentials
SET totp_enabled = false, totp_secret = NULL, backup_code_hashes = '{}', totp_attempts = 0
WHERE user_id = $1`

// Sealing of TOTP secrets: the seal.AssociatedData of a user's secret is (sealPurpose, table, user ID).
const (
	sealPurpose = "totp_secret"
	sealTable   = "govengers_auth_password_credentials"
	// resealBatchSize is the page size of ResealTOTPSecrets.
	resealBatchSize = 100
)

// Options configures New.
type Options struct {
	Pool *pgxpool.Pool // required; its search_path must reach the table of MigrationV1; the caller owns and closes it
	// Sealer, when set, seals TOTP secrets at rest (seal.AssociatedData purpose "totp_secret", table
	// "govengers_auth_password_credentials", row the user ID). Reads accept sealed and plaintext secrets, so
	// rows written before the Sealer was set keep working; ResealTOTPSecrets seals them. Without a Sealer
	// secrets are stored as given and a sealed one fails to read.
	Sealer *seal.Sealer
}

// Storage implements password.Storage on PostgreSQL. It is safe for concurrent use.
type Storage struct {
	pool   *pgxpool.Pool
	sealer *seal.Sealer
}

var _ password.Storage = (*Storage)(nil)

// New returns a Storage on options.Pool.
func New(options *Options) (*Storage, error) {
	if options == nil || options.Pool == nil {
		return nil, errors.New("postgres password storage: Options.Pool is required")
	}
	return &Storage{pool: options.Pool, sealer: options.Sealer}, nil
}

// CreateUser inserts user; a used ID, username or email (ignoring ASCII case) is password.ErrUserExists, decided by
// the table's unique indexes.
func (s *Storage) CreateUser(ctx context.Context, user *password.User) error {
	if user == nil {
		return errors.New("postgres password storage: create user: user is nil")
	}
	secret, err := s.sealSecret(user.ID, user.TOTPSecret)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, insertUser, user.ID, user.Username, user.Email, user.PasswordHash,
		user.TOTPEnabled, secret, orEmpty(user.BackupCodeHashes))
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == uniqueViolation {
		return password.ErrUserExists
	}
	if err != nil {
		return dependency.Error("postgres password storage: create user", err)
	}
	return nil
}

// GetUserByUsername returns the user with username, ignoring ASCII case, or password.ErrUserNotFound.
func (s *Storage) GetUserByUsername(ctx context.Context, username string) (*password.User, error) {
	return s.queryIdentifier(ctx, selectUserByUsername, username)
}

// GetUserByEmail returns the user with email, ignoring ASCII case, or password.ErrUserNotFound.
func (s *Storage) GetUserByEmail(ctx context.Context, email string) (*password.User, error) {
	return s.queryIdentifier(ctx, selectUserByEmail, email)
}

// GetUserByID returns the user with id, or password.ErrUserNotFound.
func (s *Storage) GetUserByID(ctx context.Context, id uuid.UUID) (*password.User, error) {
	return s.queryUser(ctx, selectUserByID, id)
}

// UpdatePasswordHash replaces the password hash while it still equals currentHash.
func (s *Storage) UpdatePasswordHash(ctx context.Context, id uuid.UUID, currentHash, newHash string) error {
	_, err := s.update(ctx, "update password hash", updatePasswordHash, id, currentHash, newHash)
	return err
}

// ConsumeTOTPAttempt reserves one attempt below maximum and returns the attempts left, else
// password.ErrTOTPAttemptsExhausted.
func (s *Storage) ConsumeTOTPAttempt(ctx context.Context, id uuid.UUID, maximum int) (int, error) {
	var remaining int
	err := s.pool.QueryRow(ctx, consumeTOTPAttempt, id, maximum).Scan(&remaining)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := s.requireUser(ctx, id); err != nil {
			return 0, err
		}
		return 0, password.ErrTOTPAttemptsExhausted
	}
	if err != nil {
		return 0, dependency.Error("postgres password storage: consume TOTP attempt", err)
	}
	return remaining, nil
}

// ResetTOTPAttempts sets the attempt counter to zero.
func (s *Storage) ResetTOTPAttempts(ctx context.Context, id uuid.UUID) error {
	_, err := s.update(ctx, "reset TOTP attempts", resetTOTPAttempts, id)
	return err
}

// ConsumeTOTPStep records step when it is later than the last one and reports whether it was.
func (s *Storage) ConsumeTOTPStep(ctx context.Context, id uuid.UUID, step time.Time) (bool, error) {
	return s.update(ctx, "consume TOTP step", consumeTOTPStep, id, step)
}

// ConsumeBackupCode removes hash from the backup codes and reports whether it was there.
func (s *Storage) ConsumeBackupCode(ctx context.Context, id uuid.UUID, hash string) (bool, error) {
	return s.update(ctx, "consume backup code", consumeBackupCode, id, hash)
}

// SetTOTP enables TOTP and resets the attempt counter while TOTP is disabled and reports whether it did.
func (s *Storage) SetTOTP(ctx context.Context, id uuid.UUID, secret string, backupCodeHashes []string) (bool, error) {
	stored, err := s.sealSecret(id, &secret)
	if err != nil {
		return false, err
	}
	return s.update(ctx, "set TOTP", setTOTP, id, stored, orEmpty(backupCodeHashes))
}

// ClearTOTP disables TOTP, clears the secret and the backup codes and resets the attempt counter.
func (s *Storage) ClearTOTP(ctx context.Context, id uuid.UUID) error {
	_, err := s.update(ctx, "clear TOTP", clearTOTP, id)
	return err
}

// update runs a statement on the user id ($1) and reports whether it changed the row; when it did not, a
// missing user is password.ErrUserNotFound and anything else a condition that did not hold.
func (s *Storage) update(ctx context.Context, operation, statement string, id uuid.UUID, arguments ...any) (bool, error) {
	tag, err := s.pool.Exec(ctx, statement, append([]any{id}, arguments...)...)
	if err != nil {
		return false, dependency.Error("postgres password storage: "+operation, err)
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}
	return false, s.requireUser(ctx, id)
}

// requireUser returns password.ErrUserNotFound when no user has id.
func (s *Storage) requireUser(ctx context.Context, id uuid.UUID) error {
	var exists bool
	if err := s.pool.QueryRow(ctx, userExists, id).Scan(&exists); err != nil {
		return dependency.Error("postgres password storage: look up user", err)
	}
	if !exists {
		return password.ErrUserNotFound
	}
	return nil
}

// queryIdentifier looks up a login identifier as typed: one PostgreSQL text cannot hold (a NUL byte, invalid
// UTF-8) names no stored user, so it is password.ErrUserNotFound without a query instead of an encoding error.
// The provider filters NUL bytes already; this covers application code calling the lookups directly.
func (s *Storage) queryIdentifier(ctx context.Context, statement, identifier string) (*password.User, error) {
	if !utf8.ValidString(identifier) || strings.ContainsRune(identifier, 0) {
		return nil, password.ErrUserNotFound
	}
	return s.queryUser(ctx, statement, identifier)
}

func (s *Storage) queryUser(ctx context.Context, statement string, argument any) (*password.User, error) {
	var user password.User
	err := s.pool.QueryRow(ctx, statement, argument).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.TOTPEnabled, &user.TOTPSecret, &user.BackupCodeHashes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, password.ErrUserNotFound
	}
	if err != nil {
		return nil, dependency.Error("postgres password storage: read user", err)
	}
	if len(user.BackupCodeHashes) == 0 {
		user.BackupCodeHashes = nil // the empty array of a user without codes, as password.User has it
	}
	if user.TOTPSecret, err = s.openSecret(user.ID, user.TOTPSecret); err != nil {
		return nil, err
	}
	return &user, nil
}

// ResealTOTPSecrets brings every stored TOTP secret under the Sealer's primary key: it seals plaintext
// secrets (rows written before Options.Sealer was set) and reseals the ones of an older key, and returns how
// many rows it changed. Run it after setting the Sealer and after putting a new key first in the ring, then
// remove the old key. It pages through the table in user ID order, one statement per changed row, each
// swapping only while the row still holds the value read, so concurrent TOTP changes win. It stops at the
// first secret that does not open (bound to another row, or of a key the ring lacks), naming the user;
// running it again continues where the rows still need it. Without a Sealer it is an error.
func (s *Storage) ResealTOTPSecrets(ctx context.Context) (int, error) {
	if s.sealer == nil {
		return 0, errors.New("postgres password storage: reseal TOTP secrets: Options.Sealer is not set")
	}
	changed := 0
	var after *uuid.UUID
	for {
		rows, err := s.pool.Query(ctx, selectTOTPSecrets, after, resealBatchSize)
		if err != nil {
			return changed, dependency.Error("postgres password storage: reseal TOTP secrets: read", err)
		}
		page, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (storedSecret, error) {
			var stored storedSecret
			return stored, row.Scan(&stored.id, &stored.secret)
		})
		if err != nil {
			return changed, dependency.Error("postgres password storage: reseal TOTP secrets: read", err)
		}
		for _, stored := range page {
			replaced, err := s.resealSecret(ctx, stored.id, stored.secret)
			if err != nil {
				return changed, err
			}
			if replaced {
				changed++
			}
		}
		if len(page) < resealBatchSize {
			return changed, nil
		}
		after = &page[len(page)-1].id
	}
}

// storedSecret is one row of selectTOTPSecrets.
type storedSecret struct {
	id     uuid.UUID
	secret string
}

// resealSecret writes the sealed form of one stored secret under the primary key and reports whether the
// row changed.
func (s *Storage) resealSecret(ctx context.Context, id uuid.UUID, stored string) (bool, error) {
	data := sealData(id)
	var next string
	var err error
	if seal.IsSealed(stored) {
		var resealed bool
		next, resealed, err = s.sealer.Reseal(data, stored)
		if err == nil && !resealed {
			return false, nil
		}
	} else {
		next, err = s.sealer.Seal(data, []byte(stored))
	}
	if err != nil {
		return false, fmt.Errorf("postgres password storage: reseal TOTP secret of user %s: %w", id, err)
	}
	tag, err := s.pool.Exec(ctx, replaceTOTPSecret, id, stored, next)
	if err != nil {
		return false, dependency.Error("postgres password storage: reseal TOTP secret", err)
	}
	return tag.RowsAffected() > 0, nil
}

// sealSecret returns the stored form of a user's secret: sealed with a Sealer, as given without one.
func (s *Storage) sealSecret(id uuid.UUID, secret *string) (*string, error) {
	if s.sealer == nil || secret == nil {
		return secret, nil
	}
	sealed, err := s.sealer.Seal(sealData(id), []byte(*secret))
	if err != nil {
		return nil, fmt.Errorf("postgres password storage: seal TOTP secret of user %s: %w", id, err)
	}
	return &sealed, nil
}

// openSecret returns the plaintext of a stored secret: a sealed one opened, a plaintext one (a row written
// before the Sealer was set) as it is.
func (s *Storage) openSecret(id uuid.UUID, stored *string) (*string, error) {
	if stored == nil || !seal.IsSealed(*stored) {
		return stored, nil
	}
	if s.sealer == nil {
		return nil, fmt.Errorf("postgres password storage: TOTP secret of user %s is sealed but Options.Sealer is not set", id)
	}
	plaintext, err := s.sealer.Open(sealData(id), *stored)
	if err != nil {
		return nil, fmt.Errorf("postgres password storage: open TOTP secret of user %s: %w", id, err)
	}
	return new(string(plaintext)), nil
}

func sealData(id uuid.UUID) seal.AssociatedData {
	return seal.AssociatedData{Purpose: sealPurpose, Table: sealTable, Row: id.String()}
}

// orEmpty keeps a nil slice from becoming NULL in the NOT NULL array column.
func orEmpty(hashes []string) []string {
	if hashes == nil {
		return []string{}
	}
	return hashes
}
