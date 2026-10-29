package session

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseKey(t *testing.T) {
	key := []byte("\xfb\xff\xfe0123456789abcdef0123456789abc")
	testCases := []struct {
		name    string
		encoded string
		wantErr string
	}{
		{name: "standard with padding", encoded: base64.StdEncoding.EncodeToString(key)},
		{name: "standard without padding", encoded: base64.RawStdEncoding.EncodeToString(key)},
		{name: "URL with padding", encoded: base64.URLEncoding.EncodeToString(key)},
		{name: "URL without padding", encoded: base64.RawURLEncoding.EncodeToString(key)},
		{name: "trailing newline as written by openssl", encoded: base64.StdEncoding.EncodeToString(key) + "\n"},
		{name: "empty", encoded: "", wantErr: "has 0 bytes"},
		{name: "31 bytes", encoded: base64.StdEncoding.EncodeToString(key[:31]), wantErr: "has 31 bytes"},
		{name: "33 bytes", encoded: base64.StdEncoding.EncodeToString(append(key, 'x')), wantErr: "has 33 bytes"},
		{name: "not base64", encoded: strings.Repeat("!", 44), wantErr: "not base64"},
		{name: "hex", encoded: strings.Repeat("ab", 32), wantErr: "has 48 bytes"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := ParseKey(testCase.encoded)
			if testCase.wantErr != "" {
				require.ErrorContains(t, err, testCase.wantErr)
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
