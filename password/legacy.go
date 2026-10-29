package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/govengers/auth/internal/dependency"
)

// VerifyBcrypt is a ready-made Options.LegacyVerifier for bcrypt hashes (PocketBase, Django, Rails and many
// others): it reports whether password matches storedHash. A malformed hash or an unsupported cost is an error,
// not a mismatch, so a broken import shows. bcrypt compares only the first 72 bytes of a password; the upgrade
// to Argon2id after a match keys the whole password, which is the one the user types. It is safe for
// concurrent use.
func VerifyBcrypt(password, storedHash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return false, nil
	default:
		return false, dependency.Error("verify bcrypt hash", err)
	}
}
