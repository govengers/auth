package seal

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	firstSecret  = bytes.Repeat([]byte("0123456789abcdef"), 2)
	secondSecret = bytes.Repeat([]byte("fedcba9876543210"), 2)
	totpOfAlice  = AssociatedData{Purpose: "totp_secret", Table: "users", Row: "0b6c0c43-alice"}
)

func newSealer(t *testing.T, keys ...Key) *Sealer {
	t.Helper()
	sealer, err := New(&Options{Keys: keys})
	require.NoError(t, err)
	return sealer
}

func TestSealOpensWithTheSameData(t *testing.T) {
	sealer := newSealer(t, Key{ID: "k1", Secret: firstSecret})
	first, err := sealer.Seal(totpOfAlice, []byte("JBSWY3DPEHPK3PXP"))
	require.NoError(t, err)
	second, err := sealer.Seal(totpOfAlice, []byte("JBSWY3DPEHPK3PXP"))
	require.NoError(t, err)
	require.NotEqual(t, first, second, "a random nonce per value")
	require.True(t, strings.HasPrefix(first, "v1.k1."))
	require.NotContains(t, first, "JBSWY3DPEHPK3PXP")

	plaintext, err := sealer.Open(totpOfAlice, first)
	require.NoError(t, err)
	require.Equal(t, []byte("JBSWY3DPEHPK3PXP"), plaintext)

	empty, err := sealer.Seal(totpOfAlice, nil)
	require.NoError(t, err)
	plaintext, err = sealer.Open(totpOfAlice, empty)
	require.NoError(t, err)
	require.Empty(t, plaintext)
}

func TestOpenRefusesOtherData(t *testing.T) {
	sealer := newSealer(t, Key{ID: "k1", Secret: firstSecret})
	sealed, err := sealer.Seal(AssociatedData{Purpose: "a", Table: "bc", Row: "1"}, []byte("secret"))
	require.NoError(t, err)
	testCases := []struct {
		name string
		data AssociatedData
	}{
		{name: "other purpose", data: AssociatedData{Purpose: "b", Table: "bc", Row: "1"}},
		{name: "other table", data: AssociatedData{Purpose: "a", Table: "bd", Row: "1"}},
		{name: "other row", data: AssociatedData{Purpose: "a", Table: "bc", Row: "2"}},
		{name: "fields shifted across the boundary", data: AssociatedData{Purpose: "ab", Table: "c", Row: "1"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			plaintext, err := sealer.Open(testCase.data, sealed)
			require.ErrorIs(t, err, ErrInvalid)
			require.Nil(t, plaintext)
		})
	}
}

func TestOpenRefusesMalformedAndTamperedValues(t *testing.T) {
	sealer := newSealer(t, Key{ID: "k1", Secret: firstSecret})
	sealed, err := sealer.Seal(totpOfAlice, []byte("secret"))
	require.NoError(t, err)
	ciphertext, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, "v1.k1."))
	require.NoError(t, err)
	ciphertext[len(ciphertext)-1] ^= 1
	flipped := "v1.k1." + base64.RawURLEncoding.EncodeToString(ciphertext)
	testCases := []struct {
		name   string
		sealed string
	}{
		{name: "empty", sealed: ""},
		{name: "plain text", sealed: "secret"},
		{name: "other version", sealed: "v2" + strings.TrimPrefix(sealed, "v1")},
		{name: "missing part", sealed: "v1.k1"},
		{name: "extra part", sealed: sealed + ".x"},
		{name: "invalid key ID", sealed: strings.Replace(sealed, "k1", "k 1", 1)},
		{name: "not base64", sealed: "v1.k1.!!!!"},
		{name: "padded base64", sealed: sealed + "="},
		{name: "trailing line feed", sealed: sealed + "\n"},
		{name: "carriage return inside", sealed: sealed[:10] + "\r" + sealed[10:]},
		{name: "too short for a nonce", sealed: "v1.k1.AAAA"},
		{name: "flipped bit", sealed: flipped},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			plaintext, err := sealer.Open(totpOfAlice, testCase.sealed)
			require.ErrorIs(t, err, ErrInvalid)
			require.Nil(t, plaintext)
			require.NotContains(t, err.Error(), "secret\"")
		})
	}
}

func TestZeroSealerRefusesToSeal(t *testing.T) {
	sealed, err := (&Sealer{}).Seal(totpOfAlice, []byte("secret"))
	require.ErrorContains(t, err, "build it with New")
	require.Empty(t, sealed)
}

func TestOpenNamesAnUnknownKey(t *testing.T) {
	old := newSealer(t, Key{ID: "old", Secret: firstSecret})
	sealed, err := old.Seal(totpOfAlice, []byte("secret"))
	require.NoError(t, err)

	_, err = newSealer(t, Key{ID: "new", Secret: secondSecret}).Open(totpOfAlice, sealed)
	require.ErrorIs(t, err, ErrUnknownKey)
	require.ErrorContains(t, err, `"old"`)

	_, err = newSealer(t, Key{ID: "old", Secret: secondSecret}).Open(totpOfAlice, sealed)
	require.ErrorIs(t, err, ErrInvalid, "the same ID with another secret")
}

func TestRotation(t *testing.T) {
	old := newSealer(t, Key{ID: "k1", Secret: firstSecret})
	sealedByOld, err := old.Seal(totpOfAlice, []byte("secret"))
	require.NoError(t, err)
	rotated := newSealer(t, Key{ID: "k2", Secret: secondSecret}, Key{ID: "k1", Secret: firstSecret})

	plaintext, err := rotated.Open(totpOfAlice, sealedByOld)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), plaintext)

	resealed, changed, err := rotated.Reseal(totpOfAlice, sealedByOld)
	require.NoError(t, err)
	require.True(t, changed)
	require.True(t, strings.HasPrefix(resealed, "v1.k2."))
	plaintext, err = newSealer(t, Key{ID: "k2", Secret: secondSecret}).Open(totpOfAlice, resealed)
	require.NoError(t, err, "opens once the old key is gone")
	require.Equal(t, []byte("secret"), plaintext)

	again, changed, err := rotated.Reseal(totpOfAlice, resealed)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, resealed, again)

	_, _, err = rotated.Reseal(AssociatedData{Purpose: "totp_secret", Table: "users", Row: "bob"}, sealedByOld)
	require.ErrorIs(t, err, ErrInvalid, "Reseal checks the binding")
}

func TestAssociatedDataIsRequired(t *testing.T) {
	sealer := newSealer(t, Key{ID: "k1", Secret: firstSecret})
	sealed, err := sealer.Seal(totpOfAlice, []byte("secret"))
	require.NoError(t, err)
	for _, data := range []AssociatedData{{Table: "t", Row: "r"}, {Purpose: "p", Row: "r"}, {Purpose: "p", Table: "t"}} {
		_, err := sealer.Seal(data, []byte("secret"))
		require.ErrorContains(t, err, "needs Purpose, Table and Row")
		_, err = sealer.Open(data, sealed)
		require.ErrorContains(t, err, "needs Purpose, Table and Row")
		_, _, err = sealer.Reseal(data, sealed)
		require.ErrorContains(t, err, "needs Purpose, Table and Row")
	}
}

func TestNewValidatesTheRing(t *testing.T) {
	testCases := []struct {
		name      string
		options   *Options
		wantError string
	}{
		{name: "nil options", options: nil, wantError: "at least one key"},
		{name: "no keys", options: &Options{}, wantError: "at least one key"},
		{name: "empty ID", options: &Options{Keys: []Key{{Secret: firstSecret}}}, wantError: "key 0: ID must be"},
		{name: "ID with a dot", options: &Options{Keys: []Key{{ID: "a.b", Secret: firstSecret}}}, wantError: "ID must be"},
		{name: "ID too long", options: &Options{Keys: []Key{{ID: strings.Repeat("a", 33), Secret: firstSecret}}}, wantError: "ID must be"},
		{name: "short secret", options: &Options{Keys: []Key{{ID: "k1", Secret: firstSecret[:31]}}}, wantError: "secret has 31 bytes"},
		{name: "placeholder secret", options: &Options{Keys: []Key{{ID: "k1", Secret: make([]byte, 32)}}}, wantError: "repeats a single byte"},
		{name: "duplicate ID", options: &Options{Keys: []Key{{ID: "k1", Secret: firstSecret}, {ID: "k1", Secret: secondSecret}}}, wantError: `key 1: ID "k1" is used twice`},
		{name: "duplicate secret", options: &Options{Keys: []Key{{ID: "k1", Secret: firstSecret}, {ID: "k2", Secret: firstSecret}}}, wantError: `repeats the one of key "k1"`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sealer, err := New(testCase.options)
			require.ErrorContains(t, err, testCase.wantError)
			require.Nil(t, sealer)
		})
	}
}

func TestNewCopiesTheSecrets(t *testing.T) {
	secret := bytes.Clone(firstSecret)
	sealer := newSealer(t, Key{ID: "k1", Secret: secret})
	sealed, err := sealer.Seal(totpOfAlice, []byte("secret"))
	require.NoError(t, err)
	secret[0] ^= 1
	_, err = sealer.Open(totpOfAlice, sealed)
	require.NoError(t, err)
}

func TestParseKeys(t *testing.T) {
	first := base64.StdEncoding.EncodeToString(firstSecret)
	second := base64.RawURLEncoding.EncodeToString(secondSecret)
	keys, err := ParseKeys("2026-11:" + first + " , 2026_01:" + second)
	require.NoError(t, err)
	require.Equal(t, []Key{{ID: "2026-11", Secret: firstSecret}, {ID: "2026_01", Secret: secondSecret}}, keys)

	testCases := []struct {
		name      string
		encoded   string
		wantError string
	}{
		{name: "empty", encoded: "", wantError: "key entry 0 is not"},
		{name: "no ID", encoded: first, wantError: "key entry 0 is not"},
		{name: "empty ID", encoded: ":" + first, wantError: "key entry 0 is not"},
		{name: "trailing comma", encoded: "k1:" + first + ",", wantError: "key entry 1 is not"},
		{name: "short secret", encoded: "k1:" + base64.StdEncoding.EncodeToString(firstSecret[:16]), wantError: "key entry 0 (k1): secret has 16 bytes"},
		{name: "not base64", encoded: "k1:" + strings.Repeat("!", 44), wantError: "secret is not base64"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			keys, err := ParseKeys(testCase.encoded)
			require.ErrorContains(t, err, testCase.wantError)
			require.NotContains(t, err.Error(), first)
			require.Nil(t, keys)
		})
	}
}

func TestIsSealed(t *testing.T) {
	sealed, err := newSealer(t, Key{ID: "k1", Secret: firstSecret}).Seal(totpOfAlice, []byte("JBSWY3DPEHPK3PXP"))
	require.NoError(t, err)
	require.True(t, IsSealed(sealed))
	require.True(t, IsSealed("v1.tampered"), "Open decides validity")
	for _, plaintext := range []string{"JBSWY3DPEHPK3PXP", "", "v1", "v2.k1.abc", "V1.k1.abc"} {
		require.False(t, IsSealed(plaintext), plaintext)
	}
}
