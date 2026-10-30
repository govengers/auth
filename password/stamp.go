package password

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

const (
	// credentialStampKey holds the stamp of the user's credentials when the session was opened, or when the
	// session itself last changed them. A session value, not part of the identity, so it never reaches a JWT or
	// an IdentityResponse.
	credentialStampKey    = auth.ProviderPassword + ".credential_stamp"
	credentialStampLength = 16 // bytes of the SHA-256 digest kept
)

// credentialStamp digests what authenticates user: the password hash and the second factor (TOTPEnabled and,
// while enabled, the secret). A password change, a rehash and a TOTP enrollment or removal change it; backup
// codes and TOTP attempts do not.
func credentialStamp(user *User) []byte {
	secret := ""
	if user.TOTPEnabled {
		secret = textOf(user.TOTPSecret)
	}
	digest := sha256.New()
	for _, field := range []string{user.PasswordHash, strconv.FormatBool(user.TOTPEnabled), secret} {
		digest.Write(binary.AppendUvarint(nil, uint64(len(field)))) // length-prefixed: no two field lists digest alike
		digest.Write([]byte(field))
	}
	return digest.Sum(nil)[:credentialStampLength]
}

// stampSession binds current to user's credentials, for as long as a session lives.
func (p *Provider) stampSession(ctx context.Context, current session.Session, user *User) error {
	if err := current.Put(ctx, credentialStampKey, credentialStamp(user), p.options.Sessions.MaximumAge()); err != nil {
		return fmt.Errorf("stamp session of user %s: %w", user.ID, err)
	}
	return nil
}

// checkStamp refuses a session whose credential stamp is not the one of user's current credentials: they
// changed since, or the session has none (opened before stamps existed, or not by the provider).
func checkStamp(ctx context.Context, current session.Session, user *User) error {
	stamp, found, err := current.Get(ctx, credentialStampKey)
	if err != nil {
		return fmt.Errorf("read credential stamp of user %s: %w", user.ID, err)
	}
	if !found {
		return &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session without credential stamp"}
	}
	if subtle.ConstantTimeCompare(stamp, credentialStamp(user)) != 1 {
		return &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "password or second factor changed"}
	}
	return nil
}
