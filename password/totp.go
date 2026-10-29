package password

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/session"
)

// Session keys of the provider's state (reserved, see session).
const (
	pendingKey   = providerName + ".pending"
	totpSetupKey = providerName + ".totp_setup"
	totpSetupTTL = 10 * time.Minute
)

// Challenge is the second-factor step a login answers with 202 {"challenge": ...}.
type Challenge string

// The challenges.
const (
	ChallengeTOTP      Challenge = "totp"       // verify a code at POST {prefix}/totp/verify
	ChallengeTOTPSetup Challenge = "totp_setup" // enroll at POST {prefix}/totp/setup and /totp/enable (TOTPOptions.Required)
)

// pendingPurpose is what a pending login waits for.
type pendingPurpose string

const (
	purposeVerify     pendingPurpose = "verify"
	purposeEnrollment pendingPurpose = "enrollment"
)

// pendingLogin is the session value between the password step and the second factor.
type pendingLogin struct {
	UserID    uuid.UUID      `json:"userId"`
	Purpose   pendingPurpose `json:"purpose"`
	ExpiresAt time.Time      `json:"expiresAt"`
}

type totpSetup struct {
	Secret string `json:"secret"`
}

type challengeResponse struct {
	Challenge Challenge `json:"challenge"`
}

// challengeFor returns the second-factor step user owes before a session, if any.
func (p *Provider) challengeFor(user *User) (Challenge, bool) {
	switch {
	case !p.options.TOTP.Enabled:
		return "", false
	case user.TOTPEnabled:
		return ChallengeTOTP, true
	case p.options.TOTP.Required:
		return ChallengeTOTPSetup, true
	}
	return "", false
}

// startChallenge starts a fresh session that only holds the pending login and answers 202 with challenge. It
// leaves the TOTP attempt counter alone: only a verified second factor resets it, so logging in again does not
// buy more guesses.
func (p *Provider) startChallenge(writer http.ResponseWriter, request *http.Request, user *User, challenge Challenge) reply {
	purpose := purposeVerify
	if challenge == ChallengeTOTPSetup {
		purpose = purposeEnrollment
	}
	pending := pendingLogin{UserID: user.ID, Purpose: purpose, ExpiresAt: p.now().Add(p.options.TOTP.PendingTTL)}
	if err := p.startPendingSession(writer, request, pending); err != nil {
		return refused(err)
	}
	return reply{status: http.StatusAccepted, body: challengeResponse{Challenge: challenge}, result: auth.ResultChallenge, identity: identityOf(user)}
}

func (p *Provider) startPendingSession(writer http.ResponseWriter, request *http.Request, pending pendingLogin) error {
	ctx := request.Context()
	current, err := p.options.Sessions.Start(ctx, writer, request)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(pending)
	if err != nil {
		return fmt.Errorf("encode pending login: %w", err)
	}
	return current.Put(ctx, pendingKey, encoded, p.options.TOTP.PendingTTL)
}

// openPendingLogin returns the request's pending login with purpose; none, expired or another purpose is
// ErrUnauthenticated with code no_pending_login.
func (p *Provider) openPendingLogin(ctx context.Context, request *http.Request, purpose pendingPurpose) (session.Session, pendingLogin, error) {
	current, err := p.options.Sessions.Open(request)
	if err != nil {
		return session.Session{}, pendingLogin{}, noPendingLogin("no session", err)
	}
	encoded, found, err := current.Get(ctx, pendingKey)
	if err != nil {
		return session.Session{}, pendingLogin{}, err
	}
	if !found {
		return session.Session{}, pendingLogin{}, noPendingLogin("no pending login", nil)
	}
	var pending pendingLogin
	if err := json.Unmarshal(encoded, &pending); err != nil {
		return session.Session{}, pendingLogin{}, noPendingLogin("unreadable pending login", err)
	}
	if pending.Purpose != purpose {
		return session.Session{}, pendingLogin{}, noPendingLogin("pending login waits for "+string(pending.Purpose), nil)
	}
	if !p.now().Before(pending.ExpiresAt) {
		return session.Session{}, pendingLogin{}, noPendingLogin("pending login expired", nil)
	}
	return current, pending, nil
}

func noPendingLogin(reason string, cause error) error {
	return &auth.Error{Kind: auth.ErrUnauthenticated, Code: codeNoPendingLogin, Reason: reason, Err: cause}
}

// accountName is the otpauth account label: username, else email, else ID.
func accountName(user *User) string {
	switch {
	case user.Username != nil && *user.Username != "":
		return *user.Username
	case user.Email != nil && *user.Email != "":
		return *user.Email
	}
	return user.ID.String()
}

func (p *Provider) generateKey(user *User) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      p.options.TOTP.Issuer,
		AccountName: accountName(user),
		Period:      p.options.TOTP.Period,
		Digits:      otp.Digits(p.options.TOTP.Digits),
	})
	if err != nil {
		return nil, dependency.Error("generate TOTP key", err)
	}
	return key, nil
}

// consumeTOTPCode reports whether code is a TOTP code of secret within the skew whose time step is later than the
// last one the user used, and marks its step used, so every code is accepted once.
func (p *Provider) consumeTOTPCode(ctx context.Context, id uuid.UUID, secret, code string) (bool, error) {
	step, found, err := p.codeStep(secret, code)
	if err != nil {
		return false, fmt.Errorf("check TOTP code of user %s: %w", id, err)
	}
	if !found {
		return false, nil
	}
	consumed, err := p.options.Storage.ConsumeTOTPStep(ctx, id, step)
	if err != nil {
		return false, fmt.Errorf("consume TOTP step of user %s: %w", id, err)
	}
	return consumed, nil
}

// codeStep returns the start of the time step within the skew around now whose TOTP code of secret is code. A code
// of the wrong length matches no step; a secret that does not decode is an error, not a wrong code.
func (p *Provider) codeStep(secret, code string) (time.Time, bool, error) {
	period := int64(p.options.TOTP.Period) //nolint:gosec // G115: at most maximumPeriod, checked by New
	skew := int64(p.options.TOTP.Skew)     //nolint:gosec // G115: at most maximumSkew, checked by New
	current := p.now().Unix() / period
	for counter := current - skew; counter <= current+skew; counter++ {
		step := time.Unix(counter*period, 0)
		valid, err := totp.ValidateCustom(strings.TrimSpace(code), secret, step, totp.ValidateOpts{
			Period: p.options.TOTP.Period,
			Digits: otp.Digits(p.options.TOTP.Digits),
		})
		switch {
		case errors.Is(err, otp.ErrValidateInputInvalidLength):
			return time.Time{}, false, nil
		case err != nil:
			return time.Time{}, false, dependency.Error("validate TOTP code", err)
		case valid:
			return step, true, nil
		}
	}
	return time.Time{}, false, nil
}

// newBackupCodes returns the configured number of distinct random backup codes and their Argon2id hashes; none
// when backup codes are disabled.
func (p *Provider) newBackupCodes() (codes, hashes []string, err error) {
	if p.options.TOTP.DisableBackupCodes {
		return []string{}, nil, nil
	}
	codes = make([]string, 0, p.options.TOTP.BackupCodeCount)
	hashes = make([]string, 0, p.options.TOTP.BackupCodeCount)
	for len(codes) < p.options.TOTP.BackupCodeCount {
		code, err := randomCode(p.backupCodeAlphabet, p.options.TOTP.BackupCodeLength)
		if err != nil {
			return nil, nil, err
		}
		if slices.Contains(codes, code) {
			continue // a duplicate would redeem twice
		}
		hash, err := Hash(code, p.options.HashParameters)
		if err != nil {
			return nil, nil, fmt.Errorf("hash backup code: %w", err)
		}
		codes = append(codes, code)
		hashes = append(hashes, hash)
	}
	return codes, hashes, nil
}

func randomCode(alphabet []rune, length int) (string, error) {
	code := make([]rune, length)
	size := big.NewInt(int64(len(alphabet)))
	for index := range code {
		position, err := rand.Int(rand.Reader, size)
		if err != nil {
			return "", fmt.Errorf("draw backup code character: %w", err)
		}
		code[index] = alphabet[position.Int64()]
	}
	return string(code), nil
}

// matchingBackupCode returns the hash among hashes that code verifies against. Codes are compared lower-case
// and without surrounding white space, as they were issued.
func matchingBackupCode(hashes []string, code string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(code))
	for _, hash := range hashes {
		if matched, err := Verify(normalized, hash); err == nil && matched {
			return hash, true
		}
	}
	return "", false
}

// consumeBackupCode reports whether code is one of the user's unused backup codes, which it consumes. With backup
// codes disabled none is, and one a racing request consumed first does not count.
func (p *Provider) consumeBackupCode(ctx context.Context, user *User, code string) (bool, error) {
	if p.options.TOTP.DisableBackupCodes {
		return false, nil
	}
	hash, found := matchingBackupCode(user.BackupCodeHashes, code)
	if !found {
		return false, nil
	}
	consumed, err := p.options.Storage.ConsumeBackupCode(ctx, user.ID, hash)
	if err != nil {
		return false, fmt.Errorf("consume backup code of user %s: %w", user.ID, err)
	}
	return consumed, nil
}

// totpAccount is the user a TOTP management request acts for, with the session it came in.
type totpAccount struct {
	session  session.Session
	user     *User
	identity *auth.Identity // the full session's identity; nil for a login pending enrollment
}

// sessionAccount returns the account of the request's full password session: its identity has Provider
// "password" and nobody impersonates it (TOTP changes while impersonating are forbidden).
func (p *Provider) sessionAccount(ctx context.Context, request *http.Request) (totpAccount, error) {
	current, err := p.options.Sessions.Open(request)
	if err != nil {
		return totpAccount{}, err
	}
	identity, err := current.Identity(ctx)
	if err != nil {
		return totpAccount{}, err
	}
	if identity.Impersonator != nil {
		return totpAccount{}, &auth.Error{Kind: auth.ErrForbidden, Reason: "TOTP change while impersonating"}
	}
	if identity.Provider != providerName {
		return totpAccount{}, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session of provider " + identity.Provider}
	}
	user, err := p.knownUser(ctx, identity.UserID, "session user deleted")
	if err != nil {
		return totpAccount{}, err
	}
	return totpAccount{session: current, user: user, identity: identity}, nil
}

// enrollmentAccount returns the account of a full password session or, without one, of a login pending
// enrollment.
func (p *Provider) enrollmentAccount(ctx context.Context, request *http.Request) (totpAccount, error) {
	full, sessionError := p.sessionAccount(ctx, request)
	if !errors.Is(sessionError, auth.ErrUnauthenticated) {
		return full, sessionError
	}
	current, pending, err := p.openPendingLogin(ctx, request, purposeEnrollment)
	if errors.Is(err, auth.ErrUnauthenticated) {
		return totpAccount{}, sessionError
	}
	if err != nil {
		return totpAccount{}, err
	}
	user, err := p.knownUser(ctx, pending.UserID, "enrolling user deleted")
	if err != nil {
		return totpAccount{}, err
	}
	return totpAccount{session: current, user: user}, nil
}

// outcomeIdentity is the identity an outcome names: the session's, or the enrolling user's.
func (a totpAccount) outcomeIdentity() *auth.Identity {
	if a.identity != nil {
		return a.identity
	}
	return identityOf(a.user)
}
