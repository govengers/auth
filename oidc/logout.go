package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/failure"
	"github.com/govengers/auth/internal/fetchmetadata"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/session"
)

const loggedOutPage = "<!doctype html><html><head><title>Logged out</title></head><body></body></html>"

// logoutTimeout bounds what a logout runs without the request's cancellation (session reads, OnLogout),
// so a hung backend or hook cannot hold the request. A variable so tests can shorten it.
var logoutTimeout = defaultHTTPTimeout

// handleLogout is RP-initiated logout: end the session, then send the browser to the IdP's
// end_session_endpoint with the ID token as hint, or to PostLogoutURL. A call that looks like the IdP's
// front-channel iframe (iss or sid present, or Sec-Fetch-Dest: iframe unless disabled) is handled as
// front-channel logout, for IdPs that accept only one logout URI per client. Any other cross-site request
// (logout CSRF) is refused before the session is touched.
func (p *Provider) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if p.isFrontChannelLogout(request) {
		p.handleFrontChannelLogout(writer, request)
		return
	}
	if err := fetchmetadata.RefuseCrossSite(request); err != nil {
		p.reporter.Refuse(request.Context(), writer, auth.Outcome{Action: auth.ActionLogout, Err: err})
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), logoutTimeout) // a disconnecting client must not skip the hint or OnLogout
	defer cancel()
	current, identity, identityError := p.sessionIdentity(ctx, request)
	rawIdentityToken, tokenError := p.ownIdentityToken(ctx, current, identity)
	readError := errors.Join(identityError, tokenError)
	if err := p.options.Sessions.End(ctx, writer, request); err != nil {
		p.reporter.Refuse(ctx, writer, auth.Outcome{Action: auth.ActionLogout, Err: errors.Join(err, readError), Identity: identity})
		return
	}
	p.runOnLogout(ctx, identity)
	redirect.To(writer, p.logoutLocation(rawIdentityToken))
	p.reporter.Report(ctx, auth.Outcome{Action: auth.ActionLogout, Result: auth.ResultSuccess, Identity: identity, Err: readError})
}

// handleFrontChannelLogout is OpenID Connect Front-Channel Logout 1.0: the IdP loads it in an iframe.
// It ends the session only when the session belongs to this provider and, if the IdP sent a sid, to
// that IdP session. It answers a cacheless empty page; the cookie reaches the iframe only with
// SameSite=None. Anyone who can make the browser load it can end the session (logout CSRF), which the
// spec accepts.
func (p *Provider) handleFrontChannelLogout(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store, must-revalidate")
	writer.Header().Set("Pragma", "no-cache")
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), logoutTimeout) // a disconnecting client must not skip the sid check or OnLogout
	defer cancel()
	_, identity, readError := p.sessionIdentity(ctx, request)
	if err := p.checkFrontChannelRequest(request.URL.Query(), identity); err != nil {
		p.refuseFrontChannel(writer, request, errors.Join(err, readError))
		return
	}
	if identity != nil && !p.owns(identity) {
		writeLoggedOutPage(writer) // another provider's session: not ours to end
		p.reporter.Report(ctx, auth.Outcome{Action: auth.ActionFrontChannelLogout, Result: auth.ResultSuccess})
		return
	}
	// without a readable identity this only expires the cookie (and drops what is left server-side)
	if err := p.options.Sessions.End(ctx, writer, request); err != nil {
		p.refuseFrontChannel(writer, request, errors.Join(err, readError))
		return
	}
	p.runOnLogout(ctx, identity)
	writeLoggedOutPage(writer)
	p.reporter.Report(ctx, auth.Outcome{Action: auth.ActionFrontChannelLogout, Result: auth.ResultSuccess, Identity: identity, Err: readError})
}

func (p *Provider) isFrontChannelLogout(request *http.Request) bool {
	query := request.URL.Query()
	if query.Has("iss") || query.Has("sid") {
		return true
	}
	return !p.options.DisableIframeLogoutDetection && request.Header.Get("Sec-Fetch-Dest") == "iframe"
}

// checkFrontChannelRequest requires iss and sid both non-empty or both absent, iss equal to the Issuer,
// and a sid equal to the sid claim of a session this provider owns.
func (p *Provider) checkFrontChannelRequest(query url.Values, identity *auth.Identity) error {
	issuer, sessionID := query.Get("iss"), query.Get("sid")
	switch {
	case !sentTogether(query):
		return frontChannelInvalid("iss and sid must be sent together")
	case issuer != "" && issuer != p.options.Issuer:
		return frontChannelInvalid("unexpected issuer")
	case sessionID != "" && p.ownsDifferentSession(identity, sessionID):
		return frontChannelInvalid("sid does not match the session")
	}
	return nil
}

// sentTogether reports whether iss and sid are both absent or both non-empty.
func sentTogether(query url.Values) bool {
	if !query.Has("iss") && !query.Has("sid") {
		return true
	}
	return query.Get("iss") != "" && query.Get("sid") != ""
}

// ownsDifferentSession reports whether identity logged in here, with an IdP session (sid claim) other than
// sessionID.
func (p *Provider) ownsDifferentSession(identity *auth.Identity, sessionID string) bool {
	return identity != nil && p.owns(identity) && stringClaim(identity.Real().Claims, "sid") != sessionID
}

func frontChannelInvalid(reason string) error {
	return &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "front-channel logout: " + reason}
}

// refuseFrontChannel answers plain text: the page runs in the IdP's iframe, nobody reads JSON there.
func (p *Provider) refuseFrontChannel(writer http.ResponseWriter, request *http.Request, err error) {
	status, response := auth.ResponseFor(err)
	http.Error(writer, response.Message, status)
	p.reporter.ReportFailure(request.Context(), auth.Outcome{Action: auth.ActionFrontChannelLogout, Err: err})
}

// sessionIdentity returns the request's session and its identity, nil when there is none (no cookie,
// expired, revoked). A backend failure leaves the identity nil too and is returned to degrade the
// outcome: logout ends the session all the same, only without OnLogout.
func (p *Provider) sessionIdentity(ctx context.Context, request *http.Request) (session.Session, *auth.Identity, error) {
	current, err := p.options.Sessions.Open(request)
	if err != nil {
		return session.Session{}, nil, failure.UnlessAbsent(err)
	}
	identity, err := current.Identity(ctx)
	return current, identity, failure.UnlessAbsent(err)
}

// ownIdentityToken returns the raw ID token stored at login when identity logged in through this
// provider, else "": another IdP's token is no valid hint here. A backend failure returns "" and the
// error: the logout still works, only without id_token_hint, so the IdP session stays.
func (p *Provider) ownIdentityToken(ctx context.Context, current session.Session, identity *auth.Identity) (string, error) {
	if identity == nil || !p.owns(identity) {
		return "", nil
	}
	rawIdentityToken, _, err := current.Get(ctx, p.identityTokenKey)
	return string(rawIdentityToken), err
}

// owns reports whether the real identity (the impersonator while impersonating) logged in here.
func (p *Provider) owns(identity *auth.Identity) bool {
	return identity.Real().Provider == p.options.Name
}

func (p *Provider) runOnLogout(ctx context.Context, identity *auth.Identity) {
	if p.options.OnLogout != nil && identity != nil {
		p.options.OnLogout(ctx, identity)
	}
}

func (p *Provider) logoutLocation(rawIdentityToken string) string {
	if p.endSessionEndpoint == "" || rawIdentityToken == "" {
		return p.options.PostLogoutURL
	}
	return redirect.WithQuery(p.endSessionEndpoint, url.Values{
		"client_id":                {p.options.ClientID},
		"id_token_hint":            {rawIdentityToken},
		"post_logout_redirect_uri": {p.options.PostLogoutURL},
	})
}

func writeLoggedOutPage(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(loggedOutPage)) // the IdP's iframe went away: nobody left to answer
}
