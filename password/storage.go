package password

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// Storage contract errors. Storage implementations return them; the provider branches on them with errors.Is.
var (
	ErrUserNotFound          = errors.New("user not found")
	ErrUserExists            = errors.New("user already exists")
	ErrTOTPAttemptsExhausted = errors.New("totp attempts exhausted")
)

// User is the record the provider reads from Storage. The library never deletes users and never writes profile
// fields; keep everything else about a user (creation time, roles, flags) in the application's own tables.
type User struct {
	ID               uuid.UUID
	Username         *string // nil when the user has none; at least one of Username and Email is set
	Email            *string
	PasswordHash     string   // Argon2id (Hash), or a legacy hash Options.LegacyVerifier understands
	TOTPEnabled      bool     // set by SetTOTP, cleared by ClearTOTP
	TOTPSecret       *string  // base32 TOTP secret while TOTPEnabled
	BackupCodeHashes []string // Argon2id hashes of the unused backup codes
}

// Storage persists users; the application implements it. Every method is atomic on its own and safe for
// concurrent use. The TOTP state (TOTPEnabled, TOTPSecret, BackupCodeHashes and a failed-attempt counter the
// storage keeps) changes only through the TOTP methods below.
type Storage interface {
	// CreateUser stores a new user. A username or email another user already has is ErrUserExists; let a
	// unique constraint decide it, not a lookup before the insert.
	CreateUser(ctx context.Context, user *User) error
	// GetUserByUsername returns the user with username, or ErrUserNotFound.
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	// GetUserByEmail returns the user with email, or ErrUserNotFound.
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// GetUserByID returns the user with id, or ErrUserNotFound.
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	// UpdatePasswordHash replaces the password hash only while the stored one still equals currentHash
	// (compare-and-swap, e.g. UPDATE ... WHERE id = $1 AND password_hash = $2); a mismatch is not an error, so a
	// concurrent password change is never overwritten.
	UpdatePasswordHash(ctx context.Context, id uuid.UUID, currentHash, newHash string) error
	// ConsumeTOTPAttempt reserves one second-factor attempt before a code is checked: below maximum it
	// increments the counter and returns the attempts left after this one (never negative); otherwise it changes
	// nothing and returns ErrTOTPAttemptsExhausted. Check and increment are one atomic step, e.g.
	// UPDATE ... SET attempts = attempts + 1 WHERE id = $1 AND attempts < $2 RETURNING $2 - attempts.
	ConsumeTOTPAttempt(ctx context.Context, id uuid.UUID, maximum int) (remaining int, err error)
	// ResetTOTPAttempts sets the attempt counter to zero.
	ResetTOTPAttempts(ctx context.Context, id uuid.UUID) error
	// ConsumeBackupCode removes hash from BackupCodeHashes and reports whether it was there; of two concurrent
	// calls with the same hash at most one returns true.
	ConsumeBackupCode(ctx context.Context, id uuid.UUID, hash string) (bool, error)
	// SetTOTP enables TOTP with secret and backupCodeHashes and resets the attempt counter.
	SetTOTP(ctx context.Context, id uuid.UUID, secret string, backupCodeHashes []string) error
	// ClearTOTP disables TOTP, clears the secret and the backup codes and resets the attempt counter.
	ClearTOTP(ctx context.Context, id uuid.UUID) error
}
