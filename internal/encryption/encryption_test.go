package encryption

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseKey(t *testing.T) {
	key := []byte("\xfb\xff\xfe0123456789abcdef0123456789abc")
	for _, encoded := range []string{base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key)} {
		parsed, err := ParseKey(encoded, "test key")
		require.NoError(t, err)
		require.Equal(t, key, parsed)
	}
	_, err := ParseKey("!!", "test key")
	require.EqualError(t, err, "test key is not base64")
	_, err = ParseKey(base64.StdEncoding.EncodeToString(key[:5]), "test key")
	require.EqualError(t, err, "test key has 5 bytes, want 32")
}

func TestCheckKey(t *testing.T) {
	require.NoError(t, CheckKey(bytes.Repeat([]byte("ab"), 16), "key"))
	require.EqualError(t, CheckKey(nil, "key"), "key has 0 bytes, want 32")
	require.ErrorContains(t, CheckKey(bytes.Repeat([]byte{7}, 32), "key"), "key repeats a single byte")
}

func TestDerivedCipherSeparatesInfos(t *testing.T) {
	key := bytes.Repeat([]byte("ab"), 16)
	first, err := DerivedCipher(key, "first")
	require.NoError(t, err)
	second, err := DerivedCipher(key, "second")
	require.NoError(t, err)
	sealed := first.Seal(nil, nil, []byte("value"), []byte("data")) //nolint:gosec // G407: NewGCMWithRandomNonce takes a nil nonce
	opened, err := first.Open(nil, nil, sealed, []byte("data"))
	require.NoError(t, err)
	require.Equal(t, []byte("value"), opened)
	_, err = second.Open(nil, nil, sealed, []byte("data"))
	require.Error(t, err)
}
