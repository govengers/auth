package password

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func newMemoryUser(username, email string) *User {
	user := &User{ID: uuid.New(), PasswordHash: "hash"}
	if username != "" {
		user.Username = &username
	}
	if email != "" {
		user.Email = &email
	}
	return user
}

func TestMemoryStorageCreateUser(t *testing.T) {
	storage := NewMemoryStorage()
	existing := newMemoryUser("ada", "ada@example.com")
	require.NoError(t, storage.CreateUser(t.Context(), existing))

	testCases := []struct {
		name    string
		user    *User
		wantErr error
	}{
		{name: "another user", user: newMemoryUser("grace", "grace@example.com")},
		{name: "username only", user: newMemoryUser("linus", "")},
		{name: "email only", user: newMemoryUser("", "margaret@example.com")},
		{name: "same ID", user: &User{ID: existing.ID}, wantErr: ErrUserExists},
		{name: "same username in another case", user: newMemoryUser("ADA", "other@example.com"), wantErr: ErrUserExists},
		{name: "same email in another case", user: newMemoryUser("other", "Ada@Example.com"), wantErr: ErrUserExists},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.ErrorIs(t, storage.CreateUser(t.Context(), testCase.user), testCase.wantErr)
		})
	}
	require.Error(t, storage.CreateUser(t.Context(), nil))
}

func TestMemoryStorageLookups(t *testing.T) {
	storage := NewMemoryStorage()
	user := newMemoryUser("ada", "ada@example.com")
	require.NoError(t, storage.CreateUser(t.Context(), user))

	byUsername, err := storage.GetUserByUsername(t.Context(), "Ada")
	require.NoError(t, err)
	require.Equal(t, user, byUsername)
	byEmail, err := storage.GetUserByEmail(t.Context(), "ADA@example.com")
	require.NoError(t, err)
	require.Equal(t, user, byEmail)
	byID, err := storage.GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	require.Equal(t, user, byID)

	_, err = storage.GetUserByUsername(t.Context(), "grace")
	require.ErrorIs(t, err, ErrUserNotFound)
	_, err = storage.GetUserByEmail(t.Context(), "ada")
	require.ErrorIs(t, err, ErrUserNotFound)
	_, err = storage.GetUserByID(t.Context(), uuid.New())
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestMemoryStorageSharesNothingWithCallers(t *testing.T) {
	storage := NewMemoryStorage()
	user := newMemoryUser("ada", "ada@example.com")
	require.NoError(t, storage.CreateUser(t.Context(), user))
	require.NoError(t, storage.SetTOTP(t.Context(), user.ID, "secret", []string{"first", "second"}))

	*user.Username = "changed"
	read, err := storage.GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	*read.Email = "changed@example.com"
	*read.TOTPSecret = "changed"
	read.BackupCodeHashes[0] = "changed"

	again, err := storage.GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	require.Equal(t, "ada", *again.Username)
	require.Equal(t, "ada@example.com", *again.Email)
	require.Equal(t, "secret", *again.TOTPSecret)
	require.Equal(t, []string{"first", "second"}, again.BackupCodeHashes)
}

func TestMemoryStorageUpdatePasswordHash(t *testing.T) {
	storage := NewMemoryStorage()
	user := newMemoryUser("ada", "")
	require.NoError(t, storage.CreateUser(t.Context(), user))

	require.NoError(t, storage.UpdatePasswordHash(t.Context(), user.ID, "stale", "ignored"))
	read, err := storage.GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	require.Equal(t, "hash", read.PasswordHash)

	require.NoError(t, storage.UpdatePasswordHash(t.Context(), user.ID, "hash", "new"))
	read, err = storage.GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	require.Equal(t, "new", read.PasswordHash)
}

func TestMemoryStorageTOTPAttempts(t *testing.T) {
	storage := NewMemoryStorage()
	user := newMemoryUser("ada", "")
	require.NoError(t, storage.CreateUser(t.Context(), user))
	consume := func() (int, error) { return storage.ConsumeTOTPAttempt(t.Context(), user.ID, 3) }
	spendAll := func() {
		for _, want := range []int{2, 1, 0} {
			remaining, err := consume()
			require.NoError(t, err)
			require.Equal(t, want, remaining)
		}
		_, err := consume()
		require.ErrorIs(t, err, ErrTOTPAttemptsExhausted)
	}

	spendAll()
	require.NoError(t, storage.ResetTOTPAttempts(t.Context(), user.ID))
	spendAll()
	require.NoError(t, storage.SetTOTP(t.Context(), user.ID, "secret", nil))
	spendAll()
	require.NoError(t, storage.ClearTOTP(t.Context(), user.ID))
	spendAll()
}

func TestMemoryStorageConsumeTOTPStep(t *testing.T) {
	storage := NewMemoryStorage()
	user := newMemoryUser("ada", "")
	require.NoError(t, storage.CreateUser(t.Context(), user))
	step := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	consume := func(step time.Time) bool {
		consumed, err := storage.ConsumeTOTPStep(t.Context(), user.ID, step)
		require.NoError(t, err)
		return consumed
	}

	require.True(t, consume(step))
	require.False(t, consume(step))
	require.False(t, consume(step.Add(-30*time.Second)))
	require.NoError(t, storage.SetTOTP(t.Context(), user.ID, "secret", nil))
	require.NoError(t, storage.ClearTOTP(t.Context(), user.ID))
	require.False(t, consume(step))
	require.True(t, consume(step.Add(30*time.Second)))
}

func TestMemoryStorageSetAndClearTOTP(t *testing.T) {
	storage := NewMemoryStorage()
	user := newMemoryUser("ada", "")
	require.NoError(t, storage.CreateUser(t.Context(), user))
	hashes := []string{"first"}

	require.NoError(t, storage.SetTOTP(t.Context(), user.ID, "secret", hashes))
	hashes[0] = "changed"
	enabled, err := storage.GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	require.True(t, enabled.TOTPEnabled)
	require.Equal(t, "secret", *enabled.TOTPSecret)
	require.Equal(t, []string{"first"}, enabled.BackupCodeHashes)

	require.NoError(t, storage.ClearTOTP(t.Context(), user.ID))
	cleared, err := storage.GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	require.False(t, cleared.TOTPEnabled)
	require.Nil(t, cleared.TOTPSecret)
	require.Empty(t, cleared.BackupCodeHashes)
}

func TestMemoryStorageConsumeBackupCode(t *testing.T) {
	storage := NewMemoryStorage()
	user := newMemoryUser("ada", "")
	require.NoError(t, storage.CreateUser(t.Context(), user))
	require.NoError(t, storage.SetTOTP(t.Context(), user.ID, "secret", []string{"first", "second"}))

	consumed, err := storage.ConsumeBackupCode(t.Context(), user.ID, "first")
	require.NoError(t, err)
	require.True(t, consumed)
	consumed, err = storage.ConsumeBackupCode(t.Context(), user.ID, "first")
	require.NoError(t, err)
	require.False(t, consumed)
	consumed, err = storage.ConsumeBackupCode(t.Context(), user.ID, "unknown")
	require.NoError(t, err)
	require.False(t, consumed)

	read, err := storage.GetUserByID(t.Context(), user.ID)
	require.NoError(t, err)
	require.Equal(t, []string{"second"}, read.BackupCodeHashes)
}

func TestMemoryStorageConsumeBackupCodeOnceUnderRace(t *testing.T) {
	storage := NewMemoryStorage()
	user := newMemoryUser("ada", "")
	require.NoError(t, storage.CreateUser(t.Context(), user))
	require.NoError(t, storage.SetTOTP(t.Context(), user.ID, "secret", []string{"only"}))

	var consumedCount atomic.Int32
	var waitGroup sync.WaitGroup
	for range 20 {
		waitGroup.Go(func() {
			consumed, err := storage.ConsumeBackupCode(t.Context(), user.ID, "only")
			if err == nil && consumed {
				consumedCount.Add(1)
			}
		})
	}
	waitGroup.Wait()
	require.Equal(t, int32(1), consumedCount.Load())
}

func TestMemoryStorageUnknownUser(t *testing.T) {
	storage := NewMemoryStorage()
	unknown := uuid.New()
	operations := map[string]func() error{
		"UpdatePasswordHash": func() error { return storage.UpdatePasswordHash(t.Context(), unknown, "a", "b") },
		"ConsumeTOTPAttempt": func() error {
			_, err := storage.ConsumeTOTPAttempt(t.Context(), unknown, 5)
			return err
		},
		"ResetTOTPAttempts": func() error { return storage.ResetTOTPAttempts(t.Context(), unknown) },
		"ConsumeTOTPStep": func() error {
			_, err := storage.ConsumeTOTPStep(t.Context(), unknown, time.Now())
			return err
		},
		"ConsumeBackupCode": func() error {
			_, err := storage.ConsumeBackupCode(t.Context(), unknown, "hash")
			return err
		},
		"SetTOTP":   func() error { return storage.SetTOTP(t.Context(), unknown, "secret", nil) },
		"ClearTOTP": func() error { return storage.ClearTOTP(t.Context(), unknown) },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, operation(), ErrUserNotFound)
		})
	}
}
