package password

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStorage is an in-memory Storage for tests and examples. It honours every Storage contract, matches
// usernames and emails case-insensitively and hands out copies, so callers never share its records. It is safe
// for concurrent use; the zero value is not usable, call NewMemoryStorage.
// ponytail: lookups by username and email scan every user; index them if it ever holds more than a test's worth.
type MemoryStorage struct {
	mutex sync.Mutex
	users map[uuid.UUID]*memoryUser
}

type memoryUser struct {
	user         User
	totpAttempts int
	totpStep     time.Time // start of the last used TOTP time step
}

// NewMemoryStorage returns an empty MemoryStorage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{users: map[uuid.UUID]*memoryUser{}}
}

// CreateUser stores a copy of user; a used ID, username or email is ErrUserExists.
func (s *MemoryStorage) CreateUser(_ context.Context, user *User) error {
	if user == nil {
		return errors.New("create user: user is nil")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, found := s.users[user.ID]; found {
		return ErrUserExists
	}
	for _, stored := range s.users {
		if sameText(stored.user.Username, user.Username) || sameText(stored.user.Email, user.Email) {
			return ErrUserExists
		}
	}
	s.users[user.ID] = &memoryUser{user: *cloneUser(user)}
	return nil
}

// GetUserByUsername returns a copy of the user with username, or ErrUserNotFound.
func (s *MemoryStorage) GetUserByUsername(_ context.Context, username string) (*User, error) {
	return s.find(func(user *User) bool { return sameText(user.Username, &username) })
}

// GetUserByEmail returns a copy of the user with email, or ErrUserNotFound.
func (s *MemoryStorage) GetUserByEmail(_ context.Context, email string) (*User, error) {
	return s.find(func(user *User) bool { return sameText(user.Email, &email) })
}

// GetUserByID returns a copy of the user with id, or ErrUserNotFound.
func (s *MemoryStorage) GetUserByID(_ context.Context, id uuid.UUID) (*User, error) {
	return s.find(func(user *User) bool { return user.ID == id })
}

// UpdatePasswordHash replaces the password hash while it still equals currentHash.
func (s *MemoryStorage) UpdatePasswordHash(_ context.Context, id uuid.UUID, currentHash, newHash string) error {
	return s.update(id, func(stored *memoryUser) error {
		if stored.user.PasswordHash == currentHash {
			stored.user.PasswordHash = newHash
		}
		return nil
	})
}

// ConsumeTOTPAttempt reserves one attempt below maximum, else ErrTOTPAttemptsExhausted.
func (s *MemoryStorage) ConsumeTOTPAttempt(_ context.Context, id uuid.UUID, maximum int) (int, error) {
	remaining := 0
	err := s.update(id, func(stored *memoryUser) error {
		if stored.totpAttempts >= maximum {
			return ErrTOTPAttemptsExhausted
		}
		stored.totpAttempts++
		remaining = maximum - stored.totpAttempts
		return nil
	})
	return remaining, err
}

// ResetTOTPAttempts sets the attempt counter to zero.
func (s *MemoryStorage) ResetTOTPAttempts(_ context.Context, id uuid.UUID) error {
	return s.update(id, func(stored *memoryUser) error {
		stored.totpAttempts = 0
		return nil
	})
}

// ConsumeTOTPStep records step when it is later than the last one and reports whether it was.
func (s *MemoryStorage) ConsumeTOTPStep(_ context.Context, id uuid.UUID, step time.Time) (bool, error) {
	consumed := false
	err := s.update(id, func(stored *memoryUser) error {
		consumed = step.After(stored.totpStep)
		if consumed {
			stored.totpStep = step
		}
		return nil
	})
	return consumed, err
}

// ConsumeBackupCode removes hash and reports whether it was there.
func (s *MemoryStorage) ConsumeBackupCode(_ context.Context, id uuid.UUID, hash string) (bool, error) {
	consumed := false
	err := s.update(id, func(stored *memoryUser) error {
		remaining := slices.DeleteFunc(slices.Clone(stored.user.BackupCodeHashes), func(candidate string) bool { return candidate == hash })
		consumed = len(remaining) < len(stored.user.BackupCodeHashes)
		stored.user.BackupCodeHashes = remaining
		return nil
	})
	return consumed, err
}

// SetTOTP enables TOTP and resets the attempt counter while TOTP is disabled and reports whether it did.
func (s *MemoryStorage) SetTOTP(_ context.Context, id uuid.UUID, secret string, backupCodeHashes []string) (bool, error) {
	enabled := false
	err := s.update(id, func(stored *memoryUser) error {
		if stored.user.TOTPEnabled {
			return nil
		}
		stored.user.TOTPEnabled = true
		stored.user.TOTPSecret = &secret
		stored.user.BackupCodeHashes = slices.Clone(backupCodeHashes)
		stored.totpAttempts = 0
		enabled = true
		return nil
	})
	return enabled, err
}

// ClearTOTP disables TOTP and resets the attempt counter.
func (s *MemoryStorage) ClearTOTP(_ context.Context, id uuid.UUID) error {
	return s.update(id, func(stored *memoryUser) error {
		stored.user.TOTPEnabled = false
		stored.user.TOTPSecret = nil
		stored.user.BackupCodeHashes = nil
		stored.totpAttempts = 0
		return nil
	})
}

func (s *MemoryStorage) find(matches func(user *User) bool) (*User, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, stored := range s.users {
		if matches(&stored.user) {
			return cloneUser(&stored.user), nil
		}
	}
	return nil, ErrUserNotFound
}

// update runs change on the stored user under the lock.
func (s *MemoryStorage) update(id uuid.UUID, change func(stored *memoryUser) error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	stored, found := s.users[id]
	if !found {
		return ErrUserNotFound
	}
	return change(stored)
}

// sameText reports whether both are set and equal ignoring case.
func sameText(first, second *string) bool {
	return first != nil && second != nil && strings.EqualFold(*first, *second)
}

// cloneUser returns a copy of user that shares no pointer or slice with it.
func cloneUser(user *User) *User {
	clone := *user
	clone.Username = cloneText(user.Username)
	clone.Email = cloneText(user.Email)
	clone.TOTPSecret = cloneText(user.TOTPSecret)
	clone.BackupCodeHashes = slices.Clone(user.BackupCodeHashes)
	return &clone
}

func cloneText(text *string) *string {
	if text == nil {
		return nil
	}
	return new(*text)
}
