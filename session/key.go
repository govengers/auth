package session

import "github.com/govengers/auth/internal/encryption"

// ParseKey decodes a base64 (standard or URL alphabet, padding optional) encryption key and requires exactly 32 bytes,
// not one byte repeated (all zero included). Generate one with `openssl rand -base64 32`. Errors never repeat the value.
func ParseKey(encoded string) ([]byte, error) {
	return encryption.ParseKey(encoded, "session encryption key")
}
