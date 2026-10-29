package password

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/httpjson"
)

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// login is flow F1: credentials, then a second-factor challenge or a session.
func (p *Provider) login(writer http.ResponseWriter, request *http.Request) reply {
	var body loginRequest
	if err := httpjson.Decode(writer, request, &body); err != nil {
		return refused(&auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed login request", Err: err})
	}
	user, legacy, err := p.checkCredentials(request.Context(), body.Identifier, body.Password)
	if err != nil {
		return refused(err)
	}
	var upgradeError error
	if legacy {
		upgradeError = p.upgradeHash(request.Context(), user, body.Password)
	}
	return p.continueLogin(writer, request, user, http.StatusOK).degradedBy(upgradeError)
}

// register creates a user and logs it in like a password login would (F3 register).
func (p *Provider) register(writer http.ResponseWriter, request *http.Request) reply {
	var body registerRequest
	if err := httpjson.Decode(writer, request, &body); err != nil {
		return refused(&auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed registration request", Err: err})
	}
	if err := validateRegistration(body, p.options); err != nil {
		return refused(err)
	}
	hash, err := Hash(body.Password, p.options.HashParameters)
	if err != nil {
		return refused(err)
	}
	user := &User{ID: uuid.New(), Username: body.Username, Email: body.Email, PasswordHash: hash}
	err = p.options.Storage.CreateUser(request.Context(), user)
	if errors.Is(err, ErrUserExists) {
		return refused(&auth.Error{Kind: auth.ErrConflict, Code: codeUserExists, Err: err})
	}
	if err != nil {
		return refused(fmt.Errorf("create password user: %w", err))
	}
	return p.continueLogin(writer, request, user, http.StatusCreated)
}

// logout ends the request's session, whatever it holds, and tells OnLogout about the identity it had.
func (p *Provider) logout(writer http.ResponseWriter, request *http.Request) reply {
	ctx := request.Context()
	identity := p.sessionIdentity(ctx, request)
	if err := p.options.Sessions.End(ctx, writer, request); err != nil {
		return refused(err)
	}
	if identity != nil && p.options.OnLogout != nil {
		p.options.OnLogout(ctx, identity)
	}
	return succeeded(http.StatusNoContent, nil, identity)
}

// sessionIdentity returns the identity of the request's session; nil when there is none or it cannot be read
// (End then reports a failing backend).
func (p *Provider) sessionIdentity(ctx context.Context, request *http.Request) *auth.Identity {
	current, err := p.options.Sessions.Open(request)
	if err != nil {
		return nil
	}
	identity, err := current.Identity(ctx)
	if err != nil {
		return nil
	}
	return identity
}

// continueLogin answers an authenticated user: a pending second-factor step when TOTP asks for one, else a
// session and status with the identity.
func (p *Provider) continueLogin(writer http.ResponseWriter, request *http.Request, user *User, status int) reply {
	if challenge, pending := p.challengeFor(user); pending {
		return p.startChallenge(writer, request, user, challenge)
	}
	identity, err := p.signIn(writer, request, user)
	if err != nil {
		return refused(err)
	}
	return succeeded(status, auth.NewIdentityResponse(identity), identity)
}

// checkCredentials returns the user identifier and password belong to, and whether the password matched a
// legacy hash (one to upgrade).
func (p *Provider) checkCredentials(ctx context.Context, identifier, password string) (user *User, legacy bool, err error) {
	user, err = p.lookup(ctx, identifier)
	if errors.Is(err, ErrUserNotFound) {
		// Same cost as a real check, so response times do not tell which users exist. The dummy hash is
		// well-formed, so there is no error to handle; only the cost matters.
		_, _ = Verify(password, p.dummyHash)
		return nil, false, &auth.Error{Kind: auth.ErrUnauthenticated, Code: codeInvalidCredentials, Reason: "unknown user", Err: err}
	}
	if err != nil {
		return nil, false, fmt.Errorf("look up password user: %w", err)
	}
	matched, legacy, err := p.verifyPassword(user, password)
	if err != nil {
		return nil, false, &auth.Error{Kind: auth.ErrUnauthenticated, Code: codeInvalidCredentials, Reason: "stored password hash not verifiable", Err: err}
	}
	if !matched {
		return nil, false, &auth.Error{Kind: auth.ErrUnauthenticated, Code: codeInvalidCredentials, Reason: "wrong password"}
	}
	return user, legacy, nil
}

// lookup returns the user an identifier names; a kind of identifier that is disabled finds nobody.
func (p *Provider) lookup(ctx context.Context, identifier string) (*User, error) {
	switch kindOf(identifier) {
	case identifierEmail:
		if p.options.DisableEmailLogin {
			return nil, ErrUserNotFound
		}
		return p.options.Storage.GetUserByEmail(ctx, identifier)
	default:
		if p.options.DisableUsernameLogin {
			return nil, ErrUserNotFound
		}
		return p.options.Storage.GetUserByUsername(ctx, identifier)
	}
}

// verifyPassword reports whether password matches the user's stored hash, and whether the LegacyVerifier
// decided it because the hash is not Argon2id.
func (p *Provider) verifyPassword(user *User, password string) (matched, legacy bool, err error) {
	matched, err = Verify(password, user.PasswordHash)
	if err == nil || p.options.LegacyVerifier == nil {
		return matched, false, err
	}
	matched, err = p.options.LegacyVerifier(password, user.PasswordHash)
	if err != nil {
		return false, true, fmt.Errorf("legacy password verifier: %w", err)
	}
	return matched, true, nil
}

// upgradeHash replaces the user's legacy hash with an Argon2id hash of password, unless the stored hash
// changed since the user was read (compare-and-swap).
func (p *Provider) upgradeHash(ctx context.Context, user *User, password string) error {
	newHash, err := Hash(password, p.options.HashParameters)
	if err != nil {
		return fmt.Errorf("upgrade legacy hash of user %s: %w", user.ID, err)
	}
	if err := p.options.Storage.UpdatePasswordHash(ctx, user.ID, user.PasswordHash, newHash); err != nil {
		return fmt.Errorf("upgrade legacy hash of user %s: %w", user.ID, err)
	}
	return nil
}
