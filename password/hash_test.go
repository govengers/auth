package password

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// testParameters keep Argon2id cheap (64 KiB, one pass) so the suite stays fast under -race. New refuses them
// (cost floor), so tests build providers through newFixture.
var testParameters = Parameters{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16}

const testPassword = "correct horse battery staple"

func TestHashRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		password string
	}{
		{name: "one byte", password: "x"},
		{name: "ascii", password: testPassword},
		{name: "unicode", password: "pässwörd 🔑"},
		{name: "maximum of 128 bytes", password: strings.Repeat("a", 128)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			hash, err := Hash(testCase.password, testParameters)
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(hash, "$argon2id$v=19$m=64,t=1,p=1$"), hash)

			matched, err := Verify(testCase.password, hash)
			require.NoError(t, err)
			require.True(t, matched)

			matched, err = Verify(testCase.password+"!", hash)
			require.NoError(t, err)
			require.False(t, matched)
		})
	}
}

func TestHashSaltsEveryHash(t *testing.T) {
	first, err := Hash(testPassword, testParameters)
	require.NoError(t, err)
	second, err := Hash(testPassword, testParameters)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
}

func TestHashRefuses(t *testing.T) {
	withParameters := func(change func(parameters *Parameters)) Parameters {
		parameters := testParameters
		change(&parameters)
		return parameters
	}
	testCases := []struct {
		name       string
		password   string
		parameters Parameters
	}{
		{name: "empty password", password: "", parameters: testParameters},
		{name: "password of 129 bytes", password: strings.Repeat("a", 129), parameters: testParameters},
		{name: "zero parameters", password: testPassword, parameters: Parameters{}},
		{name: "memory above the limit", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.Memory = 128*1024 + 1 })},
		{name: "zero iterations", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.Iterations = 0 })},
		{name: "iterations above the limit", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.Iterations = 51 })},
		{name: "zero parallelism", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.Parallelism = 0 })},
		{name: "parallelism above the limit", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.Parallelism = 9 })},
		{name: "salt below 16 bytes", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.SaltLength = 15 })},
		{name: "salt above 1024 bytes", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.SaltLength = 1025 })},
		{name: "key below 16 bytes", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.KeyLength = 15 })},
		{name: "key above 1024 bytes", password: testPassword, parameters: withParameters(func(parameters *Parameters) { parameters.KeyLength = 1025 })},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			hash, err := Hash(testCase.password, testCase.parameters)
			require.Error(t, err)
			require.Empty(t, hash)
		})
	}
}

func TestVerifyRefusesInvalidHashes(t *testing.T) {
	const salt = "c2FsdHNhbHRzYWx0c2FsdA" // 16 bytes
	const key = "a2V5a2V5a2V5a2V5a2V5aw"  // 16 bytes
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	require.NoError(t, err)
	testCases := []struct {
		name string
		hash string
	}{
		{name: "empty", hash: ""},
		{name: "bcrypt", hash: string(bcryptHash)},
		{name: "argon2i", hash: "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key},
		{name: "missing part", hash: "$argon2id$v=19$m=64,t=1,p=1$" + salt},
		{name: "extra part", hash: "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key + "$"},
		{name: "text before the first separator", hash: "x$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key},
		{name: "version 16", hash: "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key},
		{name: "missing parameter", hash: "$argon2id$v=19$m=64,t=1$" + salt + "$" + key},
		{name: "parameters out of order", hash: "$argon2id$v=19$t=1,m=64,p=1$" + salt + "$" + key},
		{name: "leading zero", hash: "$argon2id$v=19$m=064,t=1,p=1$" + salt + "$" + key},
		{name: "trailing text", hash: "$argon2id$v=19$m=64,t=1,p=1x$" + salt + "$" + key},
		{name: "parallelism beyond uint8", hash: "$argon2id$v=19$m=64,t=1,p=300$" + salt + "$" + key},
		{name: "zero memory", hash: "$argon2id$v=19$m=0,t=1,p=1$" + salt + "$" + key},
		{name: "memory above the limit", hash: "$argon2id$v=19$m=131073,t=1,p=1$" + salt + "$" + key},
		{name: "iterations above the limit", hash: "$argon2id$v=19$m=64,t=51,p=1$" + salt + "$" + key},
		{name: "parallelism above the limit", hash: "$argon2id$v=19$m=64,t=1,p=9$" + salt + "$" + key},
		{name: "short salt", hash: "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$" + key},
		{name: "short key", hash: "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$a2V5"},
		{name: "salt not base64", hash: "$argon2id$v=19$m=64,t=1,p=1$!!!!$" + key},
		{name: "padded key", hash: "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key + "=="},
		{name: "key above 1024 bytes", hash: "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + strings.Repeat("A", 1368)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			matched, err := Verify(testPassword, testCase.hash)
			require.ErrorIs(t, err, ErrInvalidHash)
			require.False(t, matched)
		})
	}
}

func TestDefaultParameters(t *testing.T) {
	parameters := DefaultParameters()
	require.Equal(t, Parameters{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}, parameters)
	require.NoError(t, validateCostFloor(parameters))
}

func TestVerifyBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	require.NoError(t, err)

	matched, err := VerifyBcrypt(testPassword, string(hash))
	require.NoError(t, err)
	require.True(t, matched)

	matched, err = VerifyBcrypt("wrong password", string(hash))
	require.NoError(t, err)
	require.False(t, matched)

	matched, err = VerifyBcrypt(testPassword, "not a bcrypt hash")
	require.Error(t, err)
	require.False(t, matched)
}
