package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"golang.org/x/oauth2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fetchmetadata"
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
	userMembership, err := p.sessionMembership(ctx, current)
	if err != nil {
		return nil, err
	}
	return withMembership(identity, userMembership), nil
}

// sessionMembership refetches the team membership of the user whose GitHub token current holds; refusals
// as Refresh.
func (p *Provider) sessionMembership(ctx context.Context, current session.Session) (membership, error) {
	token, err := sessionToken(ctx, current)
	if err != nil {
		return membership{}, err
	}
	teams, err := p.fetchTeams(ctx, p.apiClient(token))
	if err != nil {
		return membership{}, err
	}
	userMembership := p.membershipOf(teams)
	if !userMembership.allowed {
		return membership{}, notAllowed()
	}
	return userMembership, nil
}

// login stores state, nonce and PKCE verifier in the session (oauthlogin.Begin keeps one holding a live
// identity, else starts a new one) and redirects to GitHub.
func (p *Provider) login(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	state, err := oauthlogin.Begin(ctx, p.options.Sessions, writer, request, loginKey)
	if err != nil {
		p.reporter.Refuse(ctx, writer, auth.Outcome{Action: auth.ActionLogin, Err: fmt.Errorf("github: begin login: %w", err)})
		return
	}
	redirect.To(writer, p.oauth.AuthCodeURL(state.State, oauth2.S256ChallengeOption(state.Verifier)))
	p.reporter.Report(ctx, auth.Outcome{Action: auth.ActionLogin, Result: auth.ResultSuccess})
}

// callback verifies the login, starts the authenticated session and redirects to the return path.
func (p *Provider) callback(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	completed, err := p.completeLogin(ctx, request)
	if err != nil {
		p.reporter.RefuseCallback(ctx, writer, auth.Outcome{Action: auth.ActionCallback, Err: err, Identity: completed.identity})
		return
	}
	if err := p.startSession(ctx, writer, request, completed); err != nil {
		p.reporter.RefuseCallback(ctx, writer, auth.Outcome{Action: auth.ActionCallback, Err: err, Identity: completed.identity})
		return
	}
	redirect.To(writer, p.options.ExternalURL+completed.returnPath)
	p.reporter.Report(ctx, auth.Outcome{Action: auth.ActionCallback, Result: auth.ResultSuccess, Identity: completed.identity})
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
	if err := current.Put(ctx, tokenKey, encoded, p.options.Sessions.MaximumAge()); err != nil {
		return fmt.Errorf("github: store token: %w", err)
	}
	if err := current.SaveIdentity(ctx, completed.identity); err != nil {
		return fmt.Errorf("github: save identity: %w", err)
	}
	return nil
}

// logout ends the session, revokes the GitHub token (a failure only degrades the outcome), runs
// OnLogout and redirects to PostLogoutURL. A cross-site request (logout CSRF) is refused before the
// session is touched.
func (p *Provider) logout(writer http.ResponseWriter, request *http.Request) {
	if err := fetchmetadata.RefuseCrossSite(request); err != nil {
		p.reporter.Refuse(request.Context(), writer, auth.Outcome{Action: auth.ActionLogout, Err: err})
		return
	}
	ctx := context.WithoutCancel(request.Context()) // a disconnecting client must not skip the reads or OnLogout
	identity, token, readError := p.sessionState(ctx, request)
	if err := p.options.Sessions.End(ctx, writer, request); err != nil {
		p.reporter.Refuse(ctx, writer, auth.Outcome{Action: auth.ActionLogout, Err: errors.Join(fmt.Errorf("github: end session: %w", err), readError), Identity: identity})
		return
	}
	outcome := auth.Outcome{Action: auth.ActionLogout, Result: auth.ResultSuccess, Identity: identity, Err: readError}
	if token != nil {
		outcome.Err = errors.Join(outcome.Err, p.revokeToken(ctx, token))
	}
	if identity != nil && p.options.OnLogout != nil {
		p.options.OnLogout(ctx, identity)
	}
	redirect.To(writer, p.options.PostLogoutURL)
	p.reporter.Report(ctx, outcome)
}

// sessionState returns the identity and the GitHub token of the request's session, each nil when
// absent. A backend failure leaves them nil too and is returned to degrade the outcome: logout ends
// the session either way, but a token that could not be read stays valid at GitHub.
func (p *Provider) sessionState(ctx context.Context, request *http.Request) (*auth.Identity, *oauth2.Token, error) {
	current, err := p.options.Sessions.Open(request)
	if err != nil {
		return nil, nil, unlessAbsent(err)
	}
	identity, identityError := current.Identity(ctx)
	token, tokenError := sessionToken(ctx, current)
	return identity, token, errors.Join(unlessAbsent(identityError), unlessAbsent(tokenError))
}

// unlessAbsent returns err unless it only says that there is nothing (ErrUnauthenticated).
func unlessAbsent(err error) error {
	if errors.Is(err, auth.ErrUnauthenticated) {
		return nil
	}
	return err
}

// refreshTeams refreshes the teams of the request's GitHub session and answers its IdentityResponse. A
// cross-site request is refused before GitHub is called: it could end the session (SameSite=None cookies).
func (p *Provider) refreshTeams(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	if err := fetchmetadata.RefuseCrossSite(request); err != nil {
		p.reporter.Refuse(ctx, writer, auth.Outcome{Action: auth.ActionRefreshTeams, Err: err})
		return
	}
	identity, err := p.refreshSession(ctx, writer, request)
	if err != nil {
		p.reporter.Refuse(ctx, writer, auth.Outcome{Action: auth.ActionRefreshTeams, Err: err, Identity: identity})
		return
	}
	httpjson.Write(writer, http.StatusOK, auth.NewIdentityResponse(identity))
	p.reporter.Report(ctx, auth.Outcome{Action: auth.ActionRefreshTeams, Result: auth.ResultSuccess, Identity: identity})
}

// refreshSession refreshes and saves the real identity of the request's GitHub session. A refusal
// (token rejected, no allowed team) ends the session; when that fails, the failure is the error (the
// session is still usable, so it is no refusal). The stored identity is returned with errors after the
// session was read. A save by another request during the GitHub call is kept (saveMembership).
func (p *Provider) refreshSession(ctx context.Context, writer http.ResponseWriter, request *http.Request) (*auth.Identity, error) {
	current, err := p.options.Sessions.Open(request)
	if err != nil {
		return nil, fmt.Errorf("github: refresh teams: %w", err)
	}
	stored, err := current.Identity(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: refresh teams: %w", err)
	}
	if stored.Real().Provider != providerName {
		return stored, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "not a GitHub session"}
	}
	userMembership, err := p.sessionMembership(ctx, current)
	if errors.Is(err, auth.ErrUnauthenticated) || errors.Is(err, auth.ErrForbidden) {
		if endError := p.options.Sessions.End(ctx, writer, request); endError != nil {
			return stored, fmt.Errorf("github: end refused session: %w", endError)
		}
		return stored, err
	}
	if err != nil {
		return stored, err
	}
	return p.saveMembership(ctx, current, stored, userMembership)
}

// saveMembership saves stored with userMembership applied to its real identity, swapping against stored.
// When another request saved the session since stored was read (a deactivation, an impersonation), the
// membership is applied to that save once more, so neither change is lost. A save that changed the
// membership or the real user (a newer refresh, which may have revoked the admin role) or a second
// conflict refuses with ErrConflict: the membership read here may be the older one.
func (p *Provider) saveMembership(ctx context.Context, current session.Session, stored *auth.Identity, userMembership membership) (*auth.Identity, error) {
	for attempt := 1; ; attempt++ {
		updated := impersonation.WithReal(stored, withMembership(stored.Real(), userMembership))
		swapped, err := current.SwapIdentity(ctx, stored, updated)
		if err != nil {
			return stored, fmt.Errorf("github: save refreshed identity: %w", err)
		}
		if swapped {
			return updated, nil
		}
		if attempt == 2 {
			return stored, &auth.Error{Kind: auth.ErrConflict, Reason: "session saved by other requests during the team refresh"}
		}
		latest, err := current.Identity(ctx)
		if err != nil {
			return stored, fmt.Errorf("github: refresh teams: %w", err)
		}
		if !sameMembership(stored.Real(), latest.Real()) {
			return latest, &auth.Error{Kind: auth.ErrConflict, Reason: "team membership changed by another request during the team refresh"}
		}
		stored = latest
	}
}

// sameMembership reports whether a and b are the same GitHub user with the same teams and admin role, the
// fields withMembership owns.
func sameMembership(a, b *auth.Identity) bool {
	return a.Provider == b.Provider && a.Subject == b.Subject && slices.Equal(a.Teams, b.Teams) &&
		slices.Contains(a.Roles, auth.RoleAdmin) == slices.Contains(b.Roles, auth.RoleAdmin)
}

// sessionToken returns the GitHub token stored in current; none or undecodable: ErrUnauthenticated. The
// decode error is not kept: its text can quote the stored token.
func sessionToken(ctx context.Context, current session.Session) (*oauth2.Token, error) {
	encoded, found, err := current.Get(ctx, tokenKey)
	if err != nil {
		return nil, fmt.Errorf("github: read token: %w", err)
	}
	if !found {
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session has no GitHub token"}
	}
	var token oauth2.Token
	if err := json.Unmarshal(encoded, &token); err != nil {
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session's GitHub token does not decode"}
	}
	if token.AccessToken == "" {
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session has no GitHub token"}
	}
	return &token, nil
}
