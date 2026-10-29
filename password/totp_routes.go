package password

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/httpjson"
	"github.com/govengers/auth/session"
)

type verifyRequest struct {
	Code       string `json:"code"`
	BackupCode bool   `json:"backupCode"`
}

type setupResponse struct {
	Secret      string `json:"secret"`
	OTPAuthURL  string `json:"otpauthUrl"`
	Issuer      string `json:"issuer"`
	AccountName string `json:"accountName"`
}

type enableRequest struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

type enableResponse struct {
	BackupCodes []string `json:"backupCodes"`
}

type disableRequest struct {
	Password string `json:"password"`
}

type statusResponse struct {
	Enabled bool `json:"enabled"`
}

// verifyTOTP is flow F2: the second factor of a pending login, then a session.
func (p *Provider) verifyTOTP(writer http.ResponseWriter, request *http.Request) reply {
	ctx := request.Context()
	var body verifyRequest
	if err := httpjson.Decode(writer, request, &body); err != nil {
		return refused(&auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed TOTP verify request", Err: err})
	}
	user, err := p.resumeVerification(writer, request)
	if err != nil {
		return refused(err)
	}
	// The attempt is spent before the code is checked, so concurrent requests cannot test more codes.
	remaining, err := p.options.Storage.ConsumeTOTPAttempt(ctx, user.ID, p.options.TOTP.MaximumAttempts)
	if errors.Is(err, ErrTOTPAttemptsExhausted) {
		return refused(p.endPendingLogin(writer, request, codeInvalidTOTPCode, "attempts exhausted"))
	}
	if err != nil {
		return refused(fmt.Errorf("consume TOTP attempt of user %s: %w", user.ID, err))
	}
	var verified bool
	if body.BackupCode {
		verified, err = p.consumeBackupCode(ctx, user, body.Code)
	} else {
		verified, err = p.consumeTOTPCode(ctx, user.ID, *user.TOTPSecret, body.Code)
	}
	if err != nil {
		return refused(err)
	}
	if !verified && remaining == 0 {
		return refused(p.endPendingLogin(writer, request, codeInvalidTOTPCode, "wrong code, last attempt"))
	}
	if !verified {
		return refused(&auth.Error{Kind: auth.ErrUnauthenticated, Code: codeInvalidTOTPCode, Reason: "wrong code"})
	}
	if err := p.options.Storage.ResetTOTPAttempts(ctx, user.ID); err != nil {
		return refused(fmt.Errorf("reset TOTP attempts of user %s: %w", user.ID, err))
	}
	identity, err := p.signIn(writer, request, user)
	if err != nil {
		return refused(err)
	}
	return succeeded(http.StatusOK, auth.NewIdentityResponse(identity), identity)
}

// resumeVerification returns the user of the request's login pending verification. When that user is gone or
// has no TOTP any more, it ends the pending session.
func (p *Provider) resumeVerification(writer http.ResponseWriter, request *http.Request) (*User, error) {
	ctx := request.Context()
	_, pending, err := p.openPendingLogin(ctx, request, purposeVerify)
	if err != nil {
		return nil, err
	}
	user, err := p.options.Storage.GetUserByID(ctx, pending.UserID)
	if errors.Is(err, ErrUserNotFound) || err == nil && (!user.TOTPEnabled || user.TOTPSecret == nil) {
		return nil, p.endPendingLogin(writer, request, codeNoPendingLogin, "user gone or without TOTP")
	}
	if err != nil {
		return nil, fmt.Errorf("read password user %s: %w", pending.UserID, err)
	}
	return user, nil
}

// endPendingLogin ends the request's session and returns the refusal to answer with; a failed revocation is
// returned instead, so it is reported as the failure it is.
func (p *Provider) endPendingLogin(writer http.ResponseWriter, request *http.Request, code, reason string) error {
	if err := p.options.Sessions.End(request.Context(), writer, request); err != nil {
		return err
	}
	return &auth.Error{Kind: auth.ErrUnauthenticated, Code: code, Reason: reason}
}

// totpStatus answers whether the user of the full session has TOTP enabled.
func (p *Provider) totpStatus(_ http.ResponseWriter, request *http.Request) reply {
	account, err := p.sessionAccount(request.Context(), request)
	if err != nil {
		return refused(err)
	}
	return succeeded(http.StatusOK, statusResponse{Enabled: account.user.TOTPEnabled}, account.identity)
}

// setupTOTP generates a TOTP secret for a full session or a login pending enrollment and keeps it in the
// session until enable confirms it.
func (p *Provider) setupTOTP(writer http.ResponseWriter, request *http.Request) reply {
	ctx := request.Context()
	if err := httpjson.Decode(writer, request, &struct{}{}); err != nil {
		return refused(&auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed TOTP setup request", Err: err})
	}
	account, err := p.enrollmentAccount(ctx, request)
	if err != nil {
		return refused(err)
	}
	if account.user.TOTPEnabled {
		return refused(&auth.Error{Kind: auth.ErrConflict, Code: codeTOTPAlreadyEnabled})
	}
	key, err := p.generateKey(account.user)
	if err != nil {
		return refused(err)
	}
	encoded, err := json.Marshal(totpSetup{Secret: key.Secret()})
	if err != nil {
		return refused(fmt.Errorf("encode TOTP setup: %w", err))
	}
	if err := account.session.Put(ctx, totpSetupKey, encoded, totpSetupTTL); err != nil {
		return refused(err)
	}
	response := setupResponse{Secret: key.Secret(), OTPAuthURL: key.URL(), Issuer: key.Issuer(), AccountName: key.AccountName()}
	return succeeded(http.StatusOK, response, account.outcomeIdentity())
}

// enableTOTP confirms the pending setup with the password and a code, enables TOTP and answers the backup codes.
// A login pending enrollment becomes a session.
func (p *Provider) enableTOTP(writer http.ResponseWriter, request *http.Request) reply {
	ctx := request.Context()
	var body enableRequest
	if err := httpjson.Decode(writer, request, &body); err != nil {
		return refused(&auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed TOTP enable request", Err: err})
	}
	account, err := p.enrollmentAccount(ctx, request)
	if err != nil {
		return refused(err)
	}
	if account.user.TOTPEnabled {
		return refused(&auth.Error{Kind: auth.ErrConflict, Code: codeTOTPAlreadyEnabled})
	}
	if err := p.confirmPassword(account.user, body.Password); err != nil {
		return refused(err)
	}
	secret, err := popSetupSecret(ctx, account.session)
	if err != nil {
		return refused(err)
	}
	valid, err := p.consumeTOTPCode(ctx, account.user.ID, secret, body.Code)
	if err != nil {
		return refused(err)
	}
	if !valid {
		return refused(&auth.Error{Kind: auth.ErrUnauthenticated, Code: codeInvalidTOTPCode, Reason: "wrong setup code"})
	}
	codes, hashes, err := p.newBackupCodes()
	if err != nil {
		return refused(err)
	}
	identity, err := p.storeTOTP(writer, request, account, secret, hashes)
	if err != nil {
		return refused(err)
	}
	return succeeded(http.StatusOK, enableResponse{BackupCodes: codes}, identity)
}

// popSetupSecret takes the secret of the session's pending TOTP setup; none is totp_setup_missing.
func popSetupSecret(ctx context.Context, current session.Session) (string, error) {
	encoded, found, err := current.Pop(ctx, totpSetupKey)
	if err != nil {
		return "", err
	}
	var setup totpSetup
	if !found || json.Unmarshal(encoded, &setup) != nil || setup.Secret == "" {
		return "", &auth.Error{Kind: auth.ErrInvalidRequest, Code: codeTOTPSetupMissing, Reason: "no pending TOTP setup"}
	}
	return setup.Secret, nil
}

// storeTOTP enables TOTP for the account and returns the identity to answer with. A login pending enrollment
// becomes a session: OnLogin decides and the new session starts before SetTOTP, so a refused or failed login
// leaves the account unchanged, and the identity is saved after it, so no full session exists without the second
// factor.
func (p *Provider) storeTOTP(writer http.ResponseWriter, request *http.Request, account totpAccount, secret string, hashes []string) (*auth.Identity, error) {
	ctx := request.Context()
	if account.identity != nil {
		if err := p.setTOTP(ctx, account.user.ID, secret, hashes); err != nil {
			return nil, err
		}
		return account.identity, nil
	}
	current, identity, err := p.admit(writer, request, account.user)
	if err != nil {
		return nil, err
	}
	if err := p.setTOTP(ctx, account.user.ID, secret, hashes); err != nil {
		return nil, err
	}
	if err := current.SaveIdentity(ctx, identity); err != nil {
		return nil, err
	}
	return identity, nil
}

func (p *Provider) setTOTP(ctx context.Context, id uuid.UUID, secret string, hashes []string) error {
	if err := p.options.Storage.SetTOTP(ctx, id, secret, hashes); err != nil {
		return fmt.Errorf("enable TOTP of user %s: %w", id, err)
	}
	return nil
}

// disableTOTP turns TOTP off for the user of a full session after confirming the password.
func (p *Provider) disableTOTP(writer http.ResponseWriter, request *http.Request) reply {
	ctx := request.Context()
	var body disableRequest
	if err := httpjson.Decode(writer, request, &body); err != nil {
		return refused(&auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed TOTP disable request", Err: err})
	}
	account, err := p.sessionAccount(ctx, request)
	if err != nil {
		return refused(err)
	}
	if err := p.confirmPassword(account.user, body.Password); err != nil {
		return refused(err)
	}
	if !account.user.TOTPEnabled {
		return refused(&auth.Error{Kind: auth.ErrConflict, Code: codeTOTPNotEnabled})
	}
	if err := p.options.Storage.ClearTOTP(ctx, account.user.ID); err != nil {
		return refused(fmt.Errorf("disable TOTP of user %s: %w", account.user.ID, err))
	}
	return succeeded(http.StatusNoContent, nil, account.identity)
}

// confirmPassword refuses a password that is not the user's. It does not upgrade a legacy hash; login does.
func (p *Provider) confirmPassword(user *User, password string) error {
	matched, _, err := p.verifyPassword(user, password)
	if err != nil || !matched {
		return &auth.Error{Kind: auth.ErrUnauthenticated, Code: codeInvalidCredentials, Reason: "password not confirmed", Err: err}
	}
	return nil
}
