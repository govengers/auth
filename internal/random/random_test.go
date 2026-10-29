package random

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToken(t *testing.T) {
	testCases := []struct {
		name       string
		byteCount  int
		wantLength int
	}{
		{name: "session cookie value", byteCount: 32, wantLength: 43},
		{name: "one byte", byteCount: 1, wantLength: 2},
		{name: "multiple of three", byteCount: 24, wantLength: 32},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			token, err := Token(testCase.byteCount)
			require.NoError(t, err)
			require.Len(t, token, testCase.wantLength)

			decoded, err := base64.RawURLEncoding.DecodeString(token)
			require.NoError(t, err)
			require.Len(t, decoded, testCase.byteCount)
		})
	}
}

func TestTokenRejectsNonPositiveByteCount(t *testing.T) {
	for _, byteCount := range []int{0, -1} {
		token, err := Token(byteCount)
		require.Error(t, err)
		require.Empty(t, token)
	}
}

func TestTokenIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for range 1000 {
		token, err := Token(32)
		require.NoError(t, err)
		require.False(t, seen[token], "duplicate token %s", token)
		seen[token] = true
	}
}
