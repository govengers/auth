package session

import (
	"encoding/base64"
	"errors"
	"fmt"
)

const encryptionKeyLength = 32

// ParseKey decodes a base64 (standard or URL alphabet, padding optional) encryption key and requires exactly 32 bytes.
// Generate one with `openssl rand -base64 32`. Errors never repeat the value.
func ParseKey(encoded string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		key, err := encoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		if len(key) != encryptionKeyLength {
			return nil, fmt.Errorf("session encryption key has %d bytes, want %d", len(key), encryptionKeyLength)
		}
		return key, nil
	}
	return nil, errors.New("session encryption key is not base64")
}
