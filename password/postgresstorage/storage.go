package postgresstorage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/password"
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
	selectUserByUsername = selectUser + `WHERE lower(username) = lower($1)`
	selectUserByEmail    = selectUser + `WHERE lower(email) = lower($1)`
	selectUserByID       = selectUser + `WHERE user_id = $1`
)

const userExists = `SELECT EXISTS (SELECT 1 FROM govengers_auth_password_credentials WHERE user_id = $1)`

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

const clearTOTP = `
UPDATE govengers_auth_password_credentials
SET totp_enabled = false, totp_secret = NULL, backup_code_hashes = '{}', totp_attempts = 0
WHERE user_id = $1`

// Options configures New.
type Options struct {
	Pool *pgxpool.Pool // required; its search_path must reach the table of MigrationV1; the caller owns and closes it
}

// Storage implements password.Storage on PostgreSQL. It is safe for concurrent use.
type Storage struct {
	pool *pgxpool.Pool
}

var _ password.Storage = (*Storage)(nil)

// New returns a Storage on options.Pool.
func New(options *Options) (*Storage, error) {
	if options == nil || options.Pool == nil {
		return nil, errors.New("postgres password storage: Options.Pool is required")
	}
	return &Storage{pool: options.Pool}, nil
}

// CreateUser inserts user; a used ID, username or email (ignoring case) is password.ErrUserExists, decided by
// the table's unique indexes.
func (s *Storage) CreateUser(ctx context.Context, user *password.User) error {
	if user == nil {
		return errors.New("postgres password storage: create user: user is nil")
	}
	_, err := s.pool.Exec(ctx, insertUser, user.ID, user.Username, user.Email, user.PasswordHash,
		user.TOTPEnabled, user.TOTPSecret, orEmpty(user.BackupCodeHashes))
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == uniqueViolation {
		return password.ErrUserExists
	}
	if err != nil {
		return dependency.Error("postgres password storage: create user", err)
	}
	return nil
}

// GetUserByUsername returns the user with username, ignoring case, or password.ErrUserNotFound.
func (s *Storage) GetUserByUsername(ctx context.Context, username string) (*password.User, error) {
	return s.queryUser(ctx, selectUserByUsername, username)
}

// GetUserByEmail returns the user with email, ignoring case, or password.ErrUserNotFound.
func (s *Storage) GetUserByEmail(ctx context.Context, email string) (*password.User, error) {
	return s.queryUser(ctx, selectUserByEmail, email)
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
	return s.update(ctx, "set TOTP", setTOTP, id, secret, orEmpty(backupCodeHashes))
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
	return &user, nil
}

// orEmpty keeps a nil slice from becoming NULL in the NOT NULL array column.
func orEmpty(hashes []string) []string {
	if hashes == nil {
		return []string{}
	}
	return hashes
}
