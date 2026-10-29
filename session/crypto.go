package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// seal encrypts one session value with AES-256-GCM and a random 12-byte nonce (prepended). The
// additional data binds it to its session and key, so a value copied elsewhere does not decrypt.
func seal(storeKey []byte, sessionID, key string, plaintext []byte) ([]byte, error) {
	aead, err := sessionCipher(storeKey, sessionID)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plaintext, additionalData(sessionID, key)), nil
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

// sessionCipher uses a key derived per session (HKDF-SHA256), so the limit of 2^32 random nonces per
// GCM key applies to one session instead of to everything a long-lived store key ever encrypts.
func sessionCipher(storeKey []byte, sessionID string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, storeKey, nil, "govengers/auth session "+sessionID, encryptionKeyLength)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create session cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("create session cipher: %w", err)
	}
	return aead, nil
}

func additionalData(sessionID, key string) []byte {
	return []byte(sessionID + "\x00" + key)
}
