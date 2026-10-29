// Package random generates unguessable tokens for session IDs, login state and nonces.
package random

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Token returns byteCount crypto/rand bytes, base64url without padding. byteCount must be positive.
// It is safe for concurrent use.
func Token(byteCount int) (string, error) {
	if byteCount < 1 {
		return "", fmt.Errorf("random token of %d bytes: byte count must be positive", byteCount)
	}
	randomBytes := make([]byte, byteCount)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("read %d random bytes: %w", byteCount, err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
