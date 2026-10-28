package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

const tokenBytes = 32

// NewToken creates a cryptographically random opaque token. Store only its
// digest using DigestToken, and enforce expiry and revocation in the store.
func NewToken() (string, error) {
	token := make([]byte, tokenBytes)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// DigestToken returns a fixed-size SHA-256 digest suitable for storing instead
// of a bearer token.
func DigestToken(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

// TokenMatches compares a presented token with a stored digest in constant time.
func TokenMatches(token string, digest [sha256.Size]byte) bool {
	if token == "" {
		return false
	}
	actual := DigestToken(token)
	return subtle.ConstantTimeCompare(actual[:], digest[:]) == 1
}
