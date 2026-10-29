package password

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/failure"
	"github.com/govengers/auth/internal/hook"
	"github.com/govengers/auth/internal/httpjson"
	"github.com/govengers/auth/internal/random"
	"github.com/govengers/auth/session"
)

const providerName = "password"

// Client codes of the refusals (stable API for frontends).
const (
	codeInvalidCredentials = "invalid_credentials" //nolint:gosec // G101: a client code, not a credential
	codeNoPendingLogin     = "no_pending_login"
	codeInvalidTOTPCode    = "invalid_totp_code"
	codeTOTPSetupMissing   = "totp_setup_missing"
	codeTOTPAlreadyEnabled = "totp_already_enabled"
	codeTOTPNotEnabled     = "totp_not_enabled"
	codeUserExists         = "user_exists"
	codeWeakPassword       = "weak_password"
	codeInvalidUsername    = "invalid_username"
	codeInvalidEmail       = "invalid_email"
)

// Provider is the password login provider: JSON endpoints for login, an optional TOTP second factor,
// optional registration and logout, on users the application stores behind Storage. Its routes read the
// session themselves, so they need no Guard in front. It is safe for concurrent use.
type Provider struct {
	options            Options
	backupCodeAlphabet []rune
	dummyHash          string // verified for unknown users, so a lookup costs the same either way
	now                func() time.Time
	verifyHash         func(password, encodedHash string) (bool, Parameters, error) // verifyHash; tests observe the calls
	reporter           failure.Reporter
}

// New validates options, applies the defaults to a copy and precomputes the dummy hash used for unknown users
// (timing-safe lookups). It does not modify options, and changing them afterwards has no effect.
func New(options *Options) (*Provider, error) {
	if options == nil {
		return nil, errors.New("password provider: options are required")
	}
	resolved, err := resolveOptions(*options)
	if err != nil {
		return nil, err
	}
	return newProvider(resolved)
}

// newProvider builds the provider on resolved options.
func newProvider(options Options) (*Provider, error) {
	dummyPassword, err := random.Token(32)
	if err != nil {
		return nil, fmt.Errorf("password provider: %w", err)
	}
	dummyHash, err := Hash(dummyPassword, options.HashParameters)
	if err != nil {
		return nil, fmt.Errorf("password provider: dummy hash: %w", err)
	}
	return &Provider{
		options:            options,
		backupCodeAlphabet: distinctRunes(options.TOTP.BackupCodeAlphabet),
		dummyHash:          dummyHash,
		now:                time.Now,
		verifyHash:         verifyHash,
		reporter:           failure.Reporter{Provider: providerName, Observer: options.Observer},
	}, nil
}

// Name returns "password", the Identity.Provider of every identity this provider creates.
func (p *Provider) Name() string {
	return providerName
}

// Routes returns the provider's endpoints below PathPrefix: login and logout always, register with
// EnableRegistration, the TOTP endpoints with TOTP.Enabled. Register them with auth.RegisterRoutes or
// ginadapter.RegisterRoutes.
func (p *Provider) Routes() []auth.Route {
	routes := []auth.Route{
		p.route(http.MethodPost, "/login", auth.ActionLogin, p.login),
		p.route(http.MethodPost, "/logout", auth.ActionLogout, p.logout),
	}
	if p.options.EnableRegistration {
		routes = append(routes, p.route(http.MethodPost, "/register", auth.ActionRegister, p.register))
	}
	if p.options.TOTP.Enabled {
		routes = append(routes,
			p.route(http.MethodPost, "/totp/verify", auth.ActionTOTPVerify, p.verifyTOTP),
			p.route(http.MethodGet, "/totp", auth.ActionTOTPStatus, p.totpStatus),
			p.route(http.MethodPost, "/totp/setup", auth.ActionTOTPSetup, p.setupTOTP),
			p.route(http.MethodPost, "/totp/enable", auth.ActionTOTPEnable, p.enableTOTP),
			p.route(http.MethodPost, "/totp/disable", auth.ActionTOTPDisable, p.disableTOTP),
		)
	}
	return routes
}

// Refresh implements session.Refresher: it re-reads the user by the identity's UserID (the Storage user ID, which
// OnLogin must keep) and updates Username and Email, keeping every other field. A deleted user is
// ErrUnauthenticated, which ends the session.
func (p *Provider) Refresh(ctx context.Context, _ session.Session, identity *auth.Identity) (*auth.Identity, error) {
	user, err := p.knownUser(ctx, identity.UserID, "user deleted")
	if err != nil {
		return nil, err
	}
	refreshed := identity.Clone()
	refreshed.Username = textOf(user.Username)
	refreshed.Email = textOf(user.Email)
	return refreshed, nil
}

// reply is what a route answers and reports: exactly one response and one outcome per request.
type reply struct {
	status   int
	body     any // nil: no body
	result   auth.Result
	identity *auth.Identity
	err      error // the refusal or failure; decides the response
	degraded error // handled failures; reported with err, they never change the response
}

// refused answers err: a refusal with its status, anything else with 500.
func refused(err error) reply {
	return reply{result: failure.Result(err), err: err}
}

func succeeded(status int, body any, identity *auth.Identity) reply {
	return reply{status: status, body: body, result: auth.ResultSuccess, identity: identity}
}

func (p *Provider) route(method, path string, action auth.Action, handle func(writer http.ResponseWriter, request *http.Request) reply) auth.Route {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		answer := handle(writer, request)
		answer.write(writer)
		outcome := auth.Outcome{Action: action, Result: answer.result, Err: errors.Join(answer.err, answer.degraded), Identity: answer.identity}
		p.reporter.Report(request.Context(), outcome)
	})
	return auth.Route{Method: method, Path: p.options.PathPrefix + path, Handler: handler}
}

// degradedBy returns the reply with err as one more handled failure: the outcome of a success or challenge is
// degraded, a refusal or failure reports it next to its own error.
func (r reply) degradedBy(err error) reply {
	r.degraded = errors.Join(r.degraded, err)
	return r
}

// decodeRequest decodes the request's JSON body into target; a malformed body is an ErrInvalidRequest refusal
// naming the request.
func decodeRequest(writer http.ResponseWriter, request *http.Request, target any, name string) error {
	if err := httpjson.Decode(writer, request, target); err != nil {
		return &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed " + name + " request", Err: err}
	}
	return nil
}

func (r reply) write(writer http.ResponseWriter) {
	switch {
	case r.result == auth.ResultDenied || r.result == auth.ResultError:
		auth.WriteError(writer, r.err)
	case r.body == nil:
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(r.status)
	default:
		httpjson.Write(writer, r.status, r.body)
	}
}

// signIn runs OnLogin for user, starts a fresh session (revoking the request's current one) and saves the
// identity in it.
func (p *Provider) signIn(writer http.ResponseWriter, request *http.Request, user *User) (*auth.Identity, error) {
	current, identity, err := p.admit(writer, request, user)
	if err != nil {
		return nil, err
	}
	if err := current.SaveIdentity(request.Context(), identity); err != nil {
		return nil, fmt.Errorf("save session identity of user %s: %w", user.ID, err)
	}
	return identity, nil
}

// admit runs OnLogin for user and starts a fresh session (revoking the request's current one) for the identity
// it returns; saving the identity there completes the login.
func (p *Provider) admit(writer http.ResponseWriter, request *http.Request, user *User) (session.Session, *auth.Identity, error) {
	ctx := request.Context()
	identity, err := hook.RunOnLogin(ctx, p.options.OnLogin, identityOf(user))
	if err != nil {
		return session.Session{}, nil, err
	}
	if identity.UserID != user.ID {
		return session.Session{}, nil, fmt.Errorf("OnLogin replaced UserID of password user %s; Refresh and the TOTP routes look users up by it", user.ID)
	}
	current, err := p.options.Sessions.Start(ctx, writer, request)
	if err != nil {
		return session.Session{}, nil, fmt.Errorf("start session of user %s: %w", user.ID, err)
	}
	return current, identity, nil
}

func identityOf(user *User) *auth.Identity {
	return &auth.Identity{
		Provider: providerName,
		Subject:  user.ID.String(),
		UserID:   user.ID,
		Username: textOf(user.Username),
		Email:    textOf(user.Email),
		Active:   true,
	}
}

// knownUser returns the user with id; a missing one is ErrUnauthenticated with reason.
func (p *Provider) knownUser(ctx context.Context, id uuid.UUID, reason string) (*User, error) {
	user, err := p.options.Storage.GetUserByID(ctx, id)
	if errors.Is(err, ErrUserNotFound) {
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: reason, Err: err}
	}
	if err != nil {
		return nil, fmt.Errorf("read password user %s: %w", id, err)
	}
	return user, nil
}

func textOf(text *string) string {
	if text == nil {
		return ""
	}
	return *text
}
