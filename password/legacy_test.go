package password

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/govengers/auth"
)

// createLegacyUser stores a user whose password hash is storedHash.
func (f *fixture) createLegacyUser(t *testing.T, storedHash string) *User {
	t.Helper()
	user := &User{ID: uuid.New(), Username: new("ada"), PasswordHash: storedHash}
	require.NoError(t, f.storage.CreateUser(t.Context(), user))
	return user
}

func bcryptHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	return string(hash)
}

func TestLegacyLogin(t *testing.T) {
	testCases := []struct {
		name         string
		verifier     func(password, storedHash string) (bool, error)
		storedHash   string
		password     string
		wantStatus   int
		wantReason   string
		wantUpgraded bool
	}{
		{name: "bcrypt match upgrades to argon2id", verifier: VerifyBcrypt, password: testPassword, wantStatus: http.StatusOK, wantUpgraded: true},
		{name: "bcrypt mismatch", verifier: VerifyBcrypt, password: "wrong password", wantStatus: http.StatusUnauthorized, wantReason: "wrong password"},
		{name: "no legacy verifier", password: testPassword, wantStatus: http.StatusUnauthorized, wantReason: "stored password hash not verifiable"},
		{name: "malformed legacy hash", verifier: VerifyBcrypt, storedHash: "$2a$broken", password: testPassword, wantStatus: http.StatusUnauthorized, wantReason: "stored password hash not verifiable"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFixture(t, Options{LegacyVerifier: testCase.verifier})
			storedHash := testCase.storedHash
			if storedHash == "" {
				storedHash = bcryptHash(t, testPassword)
			}
			user := fixture.createLegacyUser(t, storedHash)

			recorder := fixture.newClient(t).post("/auth/password/login", map[string]any{"identifier": "ada", "password": testCase.password})

			require.Equal(t, testCase.wantStatus, recorder.Code, recorder.Body.String())
			outcome := fixture.outcomes.last(t)
			stored := fixture.storedUser(t, user.ID).PasswordHash
			if !testCase.wantUpgraded {
				var refusal *auth.Error
				require.True(t, errors.As(outcome.Err, &refusal))
				require.Equal(t, testCase.wantReason, refusal.Reason)
				require.Equal(t, storedHash, stored)
				return
			}
			require.Equal(t, auth.ResultSuccess, outcome.Result)
			require.NoError(t, outcome.Err)
			require.True(t, strings.HasPrefix(stored, "$argon2id$"), stored)
			matched, err := Verify(testPassword, stored)
			require.NoError(t, err)
			require.True(t, matched)
			require.Equal(t, http.StatusOK, fixture.newClient(t).login("ada").Code)
		})
	}
}

// resettingStorage changes the password hash to resetHash right before an upgrade writes, as a password
// reset on another replica would.
type resettingStorage struct {
	*MemoryStorage
	resetHash string
}

func (s *resettingStorage) UpdatePasswordHash(ctx context.Context, id uuid.UUID, currentHash, newHash string) error {
	if err := s.update(id, func(stored *memoryUser) error {
		stored.user.PasswordHash = s.resetHash
		return nil
	}); err != nil {
		return err
	}
	return s.MemoryStorage.UpdatePasswordHash(ctx, id, currentHash, newHash)
}

func TestLegacyUpgradeKeepsAConcurrentPasswordChange(t *testing.T) {
	fixture := newFixture(t, Options{LegacyVerifier: VerifyBcrypt})
	user := fixture.createLegacyUser(t, bcryptHash(t, testPassword))
	resetHash, err := Hash("the new password", testParameters)
	require.NoError(t, err)
	fixture.provider.options.Storage = &resettingStorage{MemoryStorage: fixture.storage, resetHash: resetHash}

	require.Equal(t, http.StatusOK, fixture.newClient(t).login("ada").Code)

	require.Equal(t, resetHash, fixture.storedUser(t, user.ID).PasswordHash)
}

func TestLegacyUpgradeFailureDegradesTheLogin(t *testing.T) {
	alwaysMatches := func(string, string) (bool, error) { return true, nil }
	testCases := []struct {
		name     string
		verifier func(password, storedHash string) (bool, error)
		failing  string
		password string
	}{
		{name: "storage fails", verifier: VerifyBcrypt, failing: "UpdatePasswordHash", password: testPassword},
		{name: "hashing fails on a password above 128 bytes", verifier: alwaysMatches, password: strings.Repeat("a", 129)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFixture(t, Options{LegacyVerifier: testCase.verifier})
			storedHash := bcryptHash(t, testPassword)
			user := fixture.createLegacyUser(t, storedHash)
			fixture.failStorage(testCase.failing)

			recorder := fixture.newClient(t).post("/auth/password/login", map[string]any{"identifier": "ada", "password": testCase.password})

			requireIdentity(t, recorder, http.StatusOK, user)
			outcome := fixture.outcomes.last(t)
			require.Equal(t, auth.ResultSuccess, outcome.Result)
			require.Error(t, outcome.Err)
			require.Equal(t, storedHash, fixture.storedUser(t, user.ID).PasswordHash)
		})
	}
}
