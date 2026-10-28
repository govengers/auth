package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonVersion       = 19
	argonMemory        = 64 * 1024
	argonIterations    = 3
	argonParallelism   = 2
	argonSaltLength    = 16
	argonKeyLength     = 32
	maxPasswordLength  = 1024
	maxArgonMemory     = 256 * 1024
	maxArgonIterations = 10
)

var (
	ErrInvalidPassword  = errors.New("password must not be empty")
	ErrPasswordTooLong  = errors.New("password exceeds maximum length")
	ErrInvalidHash      = errors.New("invalid password hash")
	ErrUnauthenticated  = errors.New("principal is not authenticated")
	ErrPermissionDenied = errors.New("permission denied")
)

// HashPassword hashes a password using Argon2id and returns a versioned,
// self-describing hash suitable for storage.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrInvalidPassword
	}
	if len(password) > maxPasswordLength {
		return "", ErrPasswordTooLong
	}

	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)

	encode := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVersion, argonMemory, argonIterations, argonParallelism, encode(salt), encode(key)), nil
}

// VerifyPassword reports whether password matches an Argon2id hash produced by
// HashPassword. Malformed or out-of-range hashes return ErrInvalidHash.
func VerifyPassword(password, encodedHash string) (bool, error) {
	if len(password) > maxPasswordLength {
		return false, ErrPasswordTooLong
	}

	params, salt, expected, err := parsePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

type argonParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func parsePasswordHash(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	version, ok := strings.CutPrefix(parts[1], "v=")
	if !ok || version != strconv.Itoa(argonVersion) {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	var params argonParams
	seen := map[string]bool{}
	for _, field := range strings.Split(parts[2], ",") {
		key, value, found := strings.Cut(field, "=")
		if !found || seen[key] {
			return argonParams{}, nil, nil, ErrInvalidHash
		}
		seen[key] = true
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return argonParams{}, nil, nil, ErrInvalidHash
		}
		switch key {
		case "m":
			params.memory = uint32(n)
		case "t":
			params.iterations = uint32(n)
		case "p":
			if n > 255 {
				return argonParams{}, nil, nil, ErrInvalidHash
			}
			params.parallelism = uint8(n)
		default:
			return argonParams{}, nil, nil, ErrInvalidHash
		}
	}
	if len(seen) != 3 ||
		params.memory < 19*1024 || params.memory > maxArgonMemory ||
		params.iterations < 2 || params.iterations > maxArgonIterations ||
		params.parallelism == 0 || params.parallelism > 4 ||
		params.memory < 8*uint32(params.parallelism) {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	decode := base64.RawStdEncoding.DecodeString
	salt, err := decode(parts[3])
	if err != nil || len(salt) < argonSaltLength || len(salt) > 64 {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	expected, err := decode(parts[4])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	return params, salt, expected, nil
}
