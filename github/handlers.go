package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/failure"
	"github.com/govengers/auth/internal/hook"
	"github.com/govengers/auth/internal/httpjson"
	"github.com/govengers/auth/internal/impersonation"
	"github.com/govengers/auth/internal/oauthlogin"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/session"
)

// completedLogin is a verified callback: the identity to store, the GitHub token and the return path.
type completedLogin struct {
	identity   *auth.Identity
	token      *oauth2.Token
	returnPath string
}

// Routes returns the provider's endpoints: GET {PathPrefix}/login, GET {PathPrefix}/callback,
// GET {PathPrefix}/logout and POST {PathPrefix}/refresh-teams. Every handler reports exactly one
// Outcome and answers with Cache-Control: no-store.
func (p *Provider) Routes() []auth.Route {
	prefix := p.options.PathPrefix
	return []auth.Route{
		{Method: http.MethodGet, Path: prefix + "/login", Handler: http.HandlerFunc(p.login)},
		{Method: http.MethodGet, Path: prefix + "/callback", Handler: http.HandlerFunc(p.callback)},
		{Method: http.MethodGet, Path: prefix + "/logout", Handler: http.HandlerFunc(p.logout)},
		{Method: http.MethodPost, Path: prefix + "/refresh-teams", Handler: http.HandlerFunc(p.refreshTeams)},
	}
}

// Refresh implements session.Refresher: it refetches the user's teams with the session's GitHub token
// and returns a copy of identity with Teams replaced and auth.RoleAdmin added or removed; every other
// field stays. GitHub rejecting the token or no token: ErrUnauthenticated; no allowed team any more:
// ErrForbidden (the Guard ends the session on both); any other failure is a plain error. It does not
// save the identity.
func (p *Provider) Refresh(ctx context.Context, current session.Session, identity *auth.Identity) (*auth.Identity, error) {
	if identity == nil {
		return nil, errors.New("github: refresh: identity is nil")
	}
	token, err := sessionToken(ctx, current)
	if err != nil {
		return nil, err
	}
	teams, err := p.fetchTeams(ctx, p.apiClient(token))
	if err != nil {
		return nil, err
	}
	userMembership := p.membershipOf(teams)
	if !userMembership.allowed {
		return nil, notAllowed()
	}
	return withMembership(identity, userMembership), nil
}

// login starts a fresh session holding state, nonce and PKCE verifier and redirects to GitHub.
func (p *Provider) login(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	state, err := oauthlogin.Begin(ctx, p.options.Sessions, writer, request, loginKey)
	if err != nil {
		p.refuse(ctx, writer, auth.Outcome{Action: auth.ActionLogin, Err: err})
		return
	}
	redirect.To(writer, p.oauth.AuthCodeURL(state.State, oauth2.S256ChallengeOption(state.Verifier)))
	p.report(ctx, auth.Outcome{Action: auth.ActionLogin, Result: auth.ResultSuccess})
}

// callback verifies the login, starts the authenticated session and redirects to the return path.
func (p *Provider) callback(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	completed, err := p.completeLogin(ctx, request)
	if err != nil {
		p.refuseCallback(ctx, writer, auth.Outcome{Action: auth.ActionCallback, Err: err, Identity: completed.identity})
		return
	}
	if err := p.startSession(ctx, writer, request, completed); err != nil {
		p.refuseCallback(ctx, writer, auth.Outcome{Action: auth.ActionCallback, Err: err, Identity: completed.identity})
		return
	}
	redirect.To(writer, p.options.ExternalURL+completed.returnPath)
	p.report(ctx, auth.Outcome{Action: auth.ActionCallback, Result: auth.ResultSuccess, Identity: completed.identity})
}

// completeLogin checks state and PKCE, reads the user and the teams and runs OnLogin. On a refusal
// after GitHub identified the user, the returned identity is set for the outcome.
func (p *Provider) completeLogin(ctx context.Context, request *http.Request) (completedLogin, error) {
	state, err := oauthlogin.Complete(ctx, p.options.Sessions, request, loginKey)
	if err != nil {
		return completedLogin{}, err
	}
	token, err := p.exchange(ctx, request.URL.Query().Get("code"), state.Verifier)
	if err != nil {
		return completedLogin{}, err
	}
	identity, err := p.identityOf(ctx, p.apiClient(token))
	if err != nil {
		return completedLogin{identity: identity}, err
	}
	mapped, err := hook.RunOnLogin(ctx, p.options.OnLogin, identity)
	if err != nil {
		return completedLogin{identity: identity}, err
	}
	return completedLogin{identity: mapped, token: token, returnPath: state.ReturnPath}, nil
}

// identityOf builds the identity of the token's user. A user in no allowed team is refused with
// ErrForbidden; the identity is returned with the refusal.
func (p *Provider) identityOf(ctx context.Context, client *http.Client) (*auth.Identity, error) {
	account, err := p.fetchUser(ctx, client)
	if err != nil {
		return nil, err
	}
	teams, err := p.fetchTeams(ctx, client)
	if err != nil {
		return nil, err
	}
	userMembership := p.membershipOf(teams)
	identity := withMembership(newIdentity(account), userMembership)
	if !userMembership.allowed {
		return identity, notAllowed()
	}
	return identity, nil
}

// startSession rotates the session (Store.Start revokes the login session) and stores token and identity.
func (p *Provider) startSession(ctx context.Context, writer http.ResponseWriter, request *http.Request, completed completedLogin) error {
	current, err := p.options.Sessions.Start(ctx, writer, request)
	if err != nil {
		return fmt.Errorf("github: start session: %w", err)
	}
	encoded, err := json.Marshal(completed.token) //nolint:gosec // G117: the token is sealed into the server-side session, never sent to the browser
	if err != nil {
		return fmt.Errorf("github: encode token: %w", err)
	}
	if err := current.Put(ctx, tokenKey, encoded, p.options.Sessions.MaxAge()); err != nil {
		return fmt.Errorf("github: store token: %w", err)
	}
	return current.SaveIdentity(ctx, completed.identity)
}

// logout ends the session, revokes the GitHub token (a failure only degrades the outcome), runs
// OnLogout and redirects to PostLogoutURL.
func (p *Provider) logout(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	identity, token, readErr := p.sessionState(context.WithoutCancel(ctx), request)
	if err := p.options.Sessions.End(ctx, writer, request); err != nil {
		p.refuse(ctx, writer, auth.Outcome{Action: auth.ActionLogout, Err: fmt.Errorf("github: end session: %w", err), Identity: identity})
		return
	}
	outcome := auth.Outcome{Action: auth.ActionLogout, Result: auth.ResultSuccess, Identity: identity, Err: readErr}
	if token != nil {
		outcome.Err = errors.Join(outcome.Err, p.revokeToken(ctx, token))
	}
	if identity != nil && p.options.OnLogout != nil {
		p.options.OnLogout(ctx, identity)
	}
	redirect.To(writer, p.options.PostLogoutURL)
	p.report(ctx, outcome)
}

// sessionState returns the identity and the GitHub token of the request's session, each nil when
// absent. A backend failure leaves them nil too and is returned to degrade the outcome: logout ends
// the session either way, but a token that could not be read stays valid at GitHub.
func (p *Provider) sessionState(ctx context.Context, request *http.Request) (*auth.Identity, *oauth2.Token, error) {
	current, err := p.options.Sessions.Open(request)
	if err != nil {
		return nil, nil, unlessAbsent(err)
	}
	identity, identityErr := current.Identity(ctx)
	token, tokenErr := sessionToken(ctx, current)
	return identity, token, errors.Join(unlessAbsent(identityErr), unlessAbsent(tokenErr))
}

// unlessAbsent returns err unless it only says that there is nothing (ErrUnauthenticated).
func unlessAbsent(err error) error {
	if errors.Is(err, auth.ErrUnauthenticated) {
		return nil
	}
	return err
}

// refreshTeams refreshes the teams of the request's GitHub session and answers its IdentityResponse.
func (p *Provider) refreshTeams(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	identity, err := p.refreshSession(ctx, writer, request)
	if err != nil {
		p.refuse(ctx, writer, auth.Outcome{Action: auth.ActionRefreshTeams, Err: err, Identity: identity})
		return
	}
	httpjson.Write(writer, http.StatusOK, auth.NewIdentityResponse(identity))
	p.report(ctx, auth.Outcome{Action: auth.ActionRefreshTeams, Result: auth.ResultSuccess, Identity: identity})
}

// refreshSession refreshes and saves the real identity of the request's GitHub session. A refusal
// (token rejected, no allowed team) ends the session; the stored identity is returned with errors after
// the session was read.
func (p *Provider) refreshSession(ctx context.Context, writer http.ResponseWriter, request *http.Request) (*auth.Identity, error) {
	current, err := p.options.Sessions.Open(request)
	if err != nil {
		return nil, err
	}
	stored, err := current.Identity(ctx)
	if err != nil {
		return nil, err
	}
	if stored.Real().Provider != providerName {
		return stored, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "not a GitHub session"}
	}
	refreshed, err := p.Refresh(ctx, current, stored.Real())
	if errors.Is(err, auth.ErrUnauthenticated) || errors.Is(err, auth.ErrForbidden) {
		return stored, errors.Join(err, p.options.Sessions.End(ctx, writer, request))
	}
	if err != nil {
		return stored, err
	}
	updated := impersonation.WithReal(stored, refreshed)
	if err := current.SaveIdentity(ctx, updated); err != nil {
		return stored, err
	}
	return updated, nil
}

// sessionToken returns the GitHub token stored in current; none or unreadable: ErrUnauthenticated.
func sessionToken(ctx context.Context, current session.Session) (*oauth2.Token, error) {
	encoded, found, err := current.Get(ctx, tokenKey)
	if err != nil {
		return nil, fmt.Errorf("github: read token: %w", err)
	}
	var token oauth2.Token
	if !found || json.Unmarshal(encoded, &token) != nil || token.AccessToken == "" {
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session has no GitHub token"}
	}
	return &token, nil
}

// refuse answers outcome.Err and reports it.
func (p *Provider) refuse(ctx context.Context, writer http.ResponseWriter, outcome auth.Outcome) {
	auth.WriteError(writer, outcome.Err)
	p.reportFailure(ctx, outcome)
}

// refuseCallback is refuse, except that with ErrorURL set the failure (a refusal or code=internal)
// redirects to ErrorURL?code=<code>.
func (p *Provider) refuseCallback(ctx context.Context, writer http.ResponseWriter, outcome auth.Outcome) {
	if p.options.ErrorURL == "" {
		p.refuse(ctx, writer, outcome)
		return
	}
	_, response := auth.ResponseFor(outcome.Err)
	redirect.To(writer, redirect.WithQuery(p.options.ErrorURL, url.Values{"code": {response.Code}}))
	p.reportFailure(ctx, outcome)
}

// reportFailure reports outcome as denied (a refusal) or error (answered with 500).
func (p *Provider) reportFailure(ctx context.Context, outcome auth.Outcome) {
	outcome.Result = failure.Result(outcome.Err)
	p.report(ctx, outcome)
}

func (p *Provider) report(ctx context.Context, outcome auth.Outcome) {
	if p.options.Observer == nil {
		return
	}
	outcome.Provider = providerName
	p.options.Observer(ctx, outcome)
}
