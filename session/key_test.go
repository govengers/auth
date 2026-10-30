package session

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseKey(t *testing.T) {
	key := []byte("\xfb\xff\xfe0123456789abcdef0123456789abc")
	testCases := []struct {
		name      string
		encoded   string
		wantError string
	}{
		{name: "standard with padding", encoded: base64.StdEncoding.EncodeToString(key)},
		{name: "standard without padding", encoded: base64.RawStdEncoding.EncodeToString(key)},
		{name: "URL with padding", encoded: base64.URLEncoding.EncodeToString(key)},
		{name: "URL without padding", encoded: base64.RawURLEncoding.EncodeToString(key)},
		{name: "trailing newline as written by openssl", encoded: base64.StdEncoding.EncodeToString(key) + "\n"},
		{name: "empty", encoded: "", wantError: "has 0 bytes"},
		{name: "31 bytes", encoded: base64.StdEncoding.EncodeToString(key[:31]), wantError: "has 31 bytes"},
		{name: "33 bytes", encoded: base64.StdEncoding.EncodeToString(append(key, 'x')), wantError: "has 33 bytes"},
		{name: "not base64", encoded: strings.Repeat("!", 44), wantError: "not base64"},
		{name: "hex", encoded: strings.Repeat("ab", 32), wantError: "has 48 bytes"},
		{name: "all zero", encoded: base64.StdEncoding.EncodeToString(make([]byte, 32)), wantError: "repeats a single byte"},
		{name: "one byte repeated", encoded: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa7}, 32)), wantError: "repeats a single byte"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := ParseKey(testCase.encoded)
			if testCase.wantError != "" {
				require.ErrorContains(t, err, testCase.wantError)
				if testCase.encoded != "" {
					require.NotContains(t, err.Error(), testCase.encoded)
				}
				require.Nil(t, parsed)
				return
			}
			require.NoError(t, err)
			require.Equal(t, key, parsed)
		})
	}
}
