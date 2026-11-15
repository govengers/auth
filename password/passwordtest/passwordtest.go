// Package passwordtest is the conformance suite for password.Storage implementations: user creation with
// case-insensitive uniqueness, lookups, copies, and every compare-and-swap contract of the TOTP and password
// methods, including the atomic ones under concurrency. password.MemoryStorage and postgresstorage run it;
// run it on your own Storage too. Use it from tests only.
package passwordtest

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/password"
)

// Run exercises every password.Storage contract. newStorage returns a fresh, empty storage for one subtest;
// the subtests run one after the other.
func Run(t *testing.T, newStorage func(t *testing.T) password.Storage) {
	t.Helper()
	testCases := []struct {
		name string
		run  func(t *testing.T, storage password.Storage)
	}{
		{name: "create user refuses used IDs, usernames and emails ignoring case", run: testCreateUser},
		{name: "lookups ignore case and find nothing for identifiers no user can have", run: testLookups},
		{name: "storage shares nothing with callers", run: testSharesNothingWithCallers},
		{name: "update password hash is a compare and swap", run: testUpdatePasswordHash},
		{name: "totp attempts count down and reset", run: testTOTPAttempts},
		{name: "totp step is consumed once and only forward", run: testConsumeTOTPStep},
		{name: "set totp only while disabled, clear totp", run: testSetAndClearTOTP},
		{name: "backup code is consumed once", run: testConsumeBackupCode},
		{name: "concurrent backup code consumption succeeds once", run: testConsumeBackupCodeOnceUnderRace},
		{name: "concurrent totp attempts never pass the maximum", run: testTOTPAttemptsUnderRace},
		{name: "unknown user", run: testUnknownUser},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.run(t, newStorage(t))
		})
	}
}

// newUser returns a user with a new ID, the password hash "hash" and username and email when not empty.
func newUser(username, email string) *password.User {
	user := &password.User{ID: uuid.New(), PasswordHash: "hash"}
	if username != "" {
		user.Username = &username
	}
	if email != "" {
		user.Email = &email
	}
	return user
}

func testCreateUser(t *testing.T, storage password.Storage) {
	existing := createUser(t, storage, "ada", "ada@example.com")
	testCases := []struct {
		name      string
		user      *password.User
		wantError error
	}{
		{name: "another user", user: newUser("grace", "grace@example.com")},
		{name: "username only", user: newUser("linus", "")},
		{name: "email only", user: newUser("", "margaret@example.com")},
		{name: "same ID", user: &password.User{ID: existing.ID, Username: new("other-id"), PasswordHash: "hash"}, wantError: password.ErrUserExists},
		{name: "same username in another case", user: newUser("ADA", "other@example.com"), wantError: password.ErrUserExists},
		{name: "same email in another case", user: newUser("other", "Ada@Example.com"), wantError: password.ErrUserExists},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.ErrorIs(t, storage.CreateUser(t.Context(), testCase.user), testCase.wantError)
		})
	}
	require.Error(t, storage.CreateUser(t.Context(), nil))
}

func testLookups(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "ada@example.com")

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
	require.ErrorIs(t, err, password.ErrUserNotFound)
	_, err = storage.GetUserByEmail(t.Context(), "ada")
	require.ErrorIs(t, err, password.ErrUserNotFound)
	_, err = storage.GetUserByID(t.Context(), uuid.New())
	require.ErrorIs(t, err, password.ErrUserNotFound)

	// The provider passes identifiers as typed: one no user can have is not found, never an error.
	for _, identifier := range []string{"ad\x00a", "ad\x00a@example.com", "caf\xff", "caf\xff@example.com"} {
		_, err = storage.GetUserByUsername(t.Context(), identifier)
		require.ErrorIs(t, err, password.ErrUserNotFound, "username %q", identifier)
		_, err = storage.GetUserByEmail(t.Context(), identifier)
		require.ErrorIs(t, err, password.ErrUserNotFound, "email %q", identifier)
	}
}

func testSharesNothingWithCallers(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "ada@example.com")
	setTOTP(t, storage, user.ID, "secret", []string{"first", "second"})

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

func testUpdatePasswordHash(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "")

	require.NoError(t, storage.UpdatePasswordHash(t.Context(), user.ID, "stale", "ignored"))
	require.Equal(t, "hash", read(t, storage, user.ID).PasswordHash)

	require.NoError(t, storage.UpdatePasswordHash(t.Context(), user.ID, "hash", "new"))
	require.Equal(t, "new", read(t, storage, user.ID).PasswordHash)
}

func testTOTPAttempts(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "")
	consume := func() (int, error) { return storage.ConsumeTOTPAttempt(t.Context(), user.ID, 3) }
	spendAll := func() {
		for _, want := range []int{2, 1, 0} {
			remaining, err := consume()
			require.NoError(t, err)
			require.Equal(t, want, remaining)
		}
		_, err := consume()
		require.ErrorIs(t, err, password.ErrTOTPAttemptsExhausted)
	}

	spendAll()
	require.NoError(t, storage.ResetTOTPAttempts(t.Context(), user.ID))
	spendAll()
	setTOTP(t, storage, user.ID, "secret", nil)
	spendAll()
	require.NoError(t, storage.ClearTOTP(t.Context(), user.ID))
	spendAll()
}

func testConsumeTOTPStep(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "")
	step := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	consume := func(step time.Time) bool {
		consumed, err := storage.ConsumeTOTPStep(t.Context(), user.ID, step)
		require.NoError(t, err)
		return consumed
	}

	require.True(t, consume(step))
	require.False(t, consume(step))
	require.False(t, consume(step.Add(-30*time.Second)))
	setTOTP(t, storage, user.ID, "secret", nil)
	require.NoError(t, storage.ClearTOTP(t.Context(), user.ID))
	require.False(t, consume(step), "SetTOTP and ClearTOTP keep the step")
	require.True(t, consume(step.Add(30*time.Second)))
}

func testSetAndClearTOTP(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "")
	hashes := []string{"first"}

	setTOTP(t, storage, user.ID, "secret", hashes)
	hashes[0] = "changed"
	enabled := read(t, storage, user.ID)
	require.True(t, enabled.TOTPEnabled)
	require.Equal(t, "secret", *enabled.TOTPSecret)
	require.Equal(t, []string{"first"}, enabled.BackupCodeHashes)

	replaced, err := storage.SetTOTP(t.Context(), user.ID, "other", []string{"other"})
	require.NoError(t, err)
	require.False(t, replaced, "an enabled second factor is never replaced")
	require.Equal(t, enabled, read(t, storage, user.ID))

	require.NoError(t, storage.ClearTOTP(t.Context(), user.ID))
	cleared := read(t, storage, user.ID)
	require.False(t, cleared.TOTPEnabled)
	require.Nil(t, cleared.TOTPSecret)
	require.Empty(t, cleared.BackupCodeHashes)
}

func testConsumeBackupCode(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "")
	setTOTP(t, storage, user.ID, "secret", []string{"first", "second"})
	consume := func(hash string) bool {
		consumed, err := storage.ConsumeBackupCode(t.Context(), user.ID, hash)
		require.NoError(t, err)
		return consumed
	}

	require.True(t, consume("first"))
	require.False(t, consume("first"))
	require.False(t, consume("unknown"))
	require.Equal(t, []string{"second"}, read(t, storage, user.ID).BackupCodeHashes)
}

func testConsumeBackupCodeOnceUnderRace(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "")
	setTOTP(t, storage, user.ID, "secret", []string{"only"})

	var consumedCount atomic.Int32
	errs := make([]error, 20)
	var waitGroup sync.WaitGroup
	for index := range errs {
		waitGroup.Go(func() {
			consumed, err := storage.ConsumeBackupCode(t.Context(), user.ID, "only")
			errs[index] = err
			if consumed {
				consumedCount.Add(1)
			}
		})
	}
	waitGroup.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), consumedCount.Load())
}

func testTOTPAttemptsUnderRace(t *testing.T, storage password.Storage) {
	user := createUser(t, storage, "ada", "")

	var reserved atomic.Int32
	errs := make([]error, 20)
	var waitGroup sync.WaitGroup
	for index := range errs {
		waitGroup.Go(func() {
			_, err := storage.ConsumeTOTPAttempt(t.Context(), user.ID, 5)
			errs[index] = err
			if err == nil {
				reserved.Add(1)
			}
		})
	}
	waitGroup.Wait()
	for _, err := range errs {
		if err != nil {
			require.ErrorIs(t, err, password.ErrTOTPAttemptsExhausted)
		}
	}
	require.Equal(t, int32(5), reserved.Load())
}

func testUnknownUser(t *testing.T, storage password.Storage) {
	unknown := uuid.New()
	operations := map[string]func() error{
		"UpdatePasswordHash": func() error { return storage.UpdatePasswordHash(t.Context(), unknown, "a", "b") },
		"ConsumeTOTPAttempt": func() error {
			_, err := storage.ConsumeTOTPAttempt(t.Context(), unknown, 5)
			return err
		},
		"ResetTOTPAttempts": func() error { return storage.ResetTOTPAttempts(t.Context(), unknown) },
		"ConsumeTOTPStep": func() error {
			_, err := storage.ConsumeTOTPStep(t.Context(), unknown, time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC))
			return err
		},
		"ConsumeBackupCode": func() error {
			_, err := storage.ConsumeBackupCode(t.Context(), unknown, "hash")
			return err
		},
		"SetTOTP": func() error {
			_, err := storage.SetTOTP(t.Context(), unknown, "secret", nil)
			return err
		},
		"ClearTOTP": func() error { return storage.ClearTOTP(t.Context(), unknown) },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, operation(), password.ErrUserNotFound)
		})
	}
}

func createUser(t *testing.T, storage password.Storage, username, email string) *password.User {
	t.Helper()
	user := newUser(username, email)
	require.NoError(t, storage.CreateUser(t.Context(), user))
	return user
}

func read(t *testing.T, storage password.Storage, id uuid.UUID) *password.User {
	t.Helper()
	user, err := storage.GetUserByID(t.Context(), id)
	require.NoError(t, err)
	return user
}

func setTOTP(t *testing.T, storage password.Storage, id uuid.UUID, secret string, hashes []string) {
	t.Helper()
	enabled, err := storage.SetTOTP(t.Context(), id, secret, hashes)
	require.NoError(t, err)
	require.True(t, enabled)
}
