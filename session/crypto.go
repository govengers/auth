package session

import (
	"crypto/cipher"
	"fmt"

	"github.com/govengers/auth/internal/encryption"
)

// seal encrypts one session value with AES-256-GCM and a random 12-byte nonce (prepended). The
// additional data binds it to its session and key, so a value copied elsewhere does not decrypt.
func seal(storeKey []byte, sessionID, key string, plaintext []byte) ([]byte, error) {
	aead, err := sessionCipher(storeKey, sessionID)
	if err != nil {
		return nil, err
	}
	// NewGCMWithRandomNonce generates the nonce itself and requires Seal's nonce argument to be nil.
	return aead.Seal(nil, nil, plaintext, additionalData(sessionID, key)), nil //nolint:gosec // G407 false positive, see above
}

// open decrypts a sealed value; false when it does not decrypt (moved, tampered, other key).
func open(storeKey []byte, sessionID, key string, sealed []byte) ([]byte, bool) {
	aead, err := sessionCipher(storeKey, sessionID)
	if err != nil {
		return nil, false
	}
	plaintext, err := aead.Open(nil, nil, sealed, additionalData(sessionID, key))
	return plaintext, err == nil
}

// sessionCipher uses a key derived per session, so the GCM nonce limit applies to one session.
func sessionCipher(storeKey []byte, sessionID string) (cipher.AEAD, error) {
	aead, err := encryption.DerivedCipher(storeKey, "govengers/auth session "+sessionID)
	if err != nil {
		return nil, fmt.Errorf("session cipher: %w", err)
	}
	return aead, nil
}

func additionalData(sessionID, key string) []byte {
	return []byte(sessionID + "\x00" + key)
}
