// Package encryption holds the AES-256-GCM primitives the session values and the seal package share: key
// parsing and checks, and a cipher under a key derived per context. Its functions are safe for concurrent use.
package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeyLength is the length of every key: AES-256.
const KeyLength = 32

// repeatedKeyProblem describes a refused placeholder key without naming its byte.
const repeatedKeyProblem = "repeats a single byte (all zero, a placeholder); generate one with `openssl rand -base64 32`"

// ParseKey decodes a base64 (standard or URL alphabet, padding optional) key and checks it with CheckKey.
// name starts the error messages; they never repeat the value.
func ParseKey(encoded, name string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		key, err := encoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		if err := CheckKey(key, name); err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, errors.New(name + " is not base64")
}

// CheckKey requires exactly KeyLength bytes, not one byte repeated (all zero included). name starts the error
// messages; they never repeat the key.
func CheckKey(key []byte, name string) error {
	if len(key) != KeyLength {
		return fmt.Errorf("%s has %d bytes, want %d", name, len(key), KeyLength)
	}
	if bytes.Count(key, key[:1]) == len(key) {
		return errors.New(name + " " + repeatedKeyProblem)
	}
	return nil
}

// DerivedCipher returns AES-256-GCM with random 12-byte nonces (prepended to the ciphertext) under the key
// HKDF-SHA256 derives from key for info. A key per context keeps the limit of 2^32 random nonces per GCM key
// to one context (a session, a sealed row) instead of everything a long-lived key ever encrypts. Seal and Open
// of the returned AEAD take a nil nonce.
func DerivedCipher(key []byte, info string) (cipher.AEAD, error) {
	derived, err := hkdf.Key(sha256.New, key, nil, info, KeyLength)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	return aead, nil
}
