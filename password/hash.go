package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Limits of the Argon2id encoding. Verify refuses hashes outside them, so a stored hash cannot make a
// verification arbitrarily expensive; Hash refuses parameters outside them, so every hash it returns verifies.
const (
	maximumMemory         = 128 * 1024 // KiB
	maximumIterations     = 50
	maximumParallelism    = 8
	minimumSaltLength     = 16
	minimumKeyLength      = 16
	maximumSaltLength     = 1024
	maximumKeyLength      = 1024
	maximumPasswordLength = 128 // bytes
)

// minimumMemory is the cost floor New enforces on Options.HashParameters.
const minimumMemory = 32 * 1024 // KiB

// ErrInvalidHash reports a stored hash that is not an Argon2id hash Verify accepts: another format, another
// Argon2 version, malformed parts or parameters outside the limits.
var ErrInvalidHash = errors.New("invalid password hash")

// Parameters are Argon2id cost parameters.
type Parameters struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParameters returns m=64 MiB, t=3, p=2, salt 16, key 32.
func DefaultParameters() Parameters {
	return Parameters{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}
}

// validate returns why parameters are outside the limits of the encoding, or nil.
func (p Parameters) validate() error {
	switch {
	case p.Memory < 1 || p.Memory > maximumMemory:
		return fmt.Errorf("memory %d KiB is outside 1..%d", p.Memory, maximumMemory)
	case p.Iterations < 1 || p.Iterations > maximumIterations:
		return fmt.Errorf("iterations %d are outside 1..%d", p.Iterations, maximumIterations)
	case p.Parallelism < 1 || p.Parallelism > maximumParallelism:
		return fmt.Errorf("parallelism %d is outside 1..%d", p.Parallelism, maximumParallelism)
	case p.SaltLength < minimumSaltLength || p.SaltLength > maximumSaltLength:
		return fmt.Errorf("salt length %d is outside %d..%d", p.SaltLength, minimumSaltLength, maximumSaltLength)
	case p.KeyLength < minimumKeyLength || p.KeyLength > maximumKeyLength:
		return fmt.Errorf("key length %d is outside %d..%d", p.KeyLength, minimumKeyLength, maximumKeyLength)
	}
	return nil
}

// validateCostFloor refuses parameters below the minimum cost or outside the limits of the encoding.
func validateCostFloor(parameters Parameters) error {
	if parameters.Memory < minimumMemory {
		return fmt.Errorf("memory %d KiB is below %d", parameters.Memory, minimumMemory)
	}
	return parameters.validate()
}

// Hash returns the Argon2id hash of password in the encoding "$argon2id$v=19$m=..,t=..,p=..$salt$hash" (salt and
// hash base64 without padding). The password must have 1..128 bytes. It is safe for concurrent use.
func Hash(password string, parameters Parameters) (string, error) {
	if len(password) < 1 || len(password) > maximumPasswordLength {
		return "", fmt.Errorf("hash password: length %d bytes is outside 1..%d", len(password), maximumPasswordLength)
	}
	if err := parameters.validate(); err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	salt := make([]byte, parameters.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("hash password: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, parameters.Iterations, parameters.Memory, parameters.Parallelism, parameters.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$%s$%s$%s", argon2.Version, encodeCost(parameters),
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches encodedHash in constant time. Anything but an Argon2id hash within
// the limits (memory 128 MiB, 50 iterations, parallelism 8, salt and key 16..1024 bytes) is ErrInvalidHash.
// It is safe for concurrent use.
func Verify(password, encodedHash string) (bool, error) {
	decoded, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(password), decoded.salt, decoded.parameters.Iterations, decoded.parameters.Memory,
		decoded.parameters.Parallelism, decoded.parameters.KeyLength)
	return subtle.ConstantTimeCompare(key, decoded.key) == 1, nil
}

type decodedHash struct {
	parameters Parameters
	salt       []byte
	key        []byte
}

// decodeHash parses the encoding Hash writes; only its canonical form is accepted.
func decodeHash(encodedHash string) (decodedHash, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return decodedHash{}, fmt.Errorf("%w: not an argon2id hash", ErrInvalidHash)
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return decodedHash{}, fmt.Errorf("%w: argon2 version %q", ErrInvalidHash, parts[2])
	}
	var parameters Parameters
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &parameters.Memory, &parameters.Iterations, &parameters.Parallelism)
	if err != nil || encodeCost(parameters) != parts[3] {
		return decodedHash{}, fmt.Errorf("%w: malformed parameters", ErrInvalidHash)
	}
	salt, saltError := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	key, keyError := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if saltError != nil || keyError != nil || len(salt) > maximumSaltLength || len(key) > maximumKeyLength {
		return decodedHash{}, fmt.Errorf("%w: malformed salt or key", ErrInvalidHash)
	}
	parameters.SaltLength = uint32(len(salt)) //nolint:gosec // G115: at most maximumSaltLength, checked above
	parameters.KeyLength = uint32(len(key))   //nolint:gosec // G115: at most maximumKeyLength, checked above
	if err := parameters.validate(); err != nil {
		return decodedHash{}, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}
	return decodedHash{parameters: parameters, salt: salt, key: key}, nil
}

func encodeCost(parameters Parameters) string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", parameters.Memory, parameters.Iterations, parameters.Parallelism)
}
