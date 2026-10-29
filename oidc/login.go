package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/oauthlogin"
)

// verifiedLogin is what a callback learned from the IdP before any hook ran.
type verifiedLogin struct {
	rawIdentityToken string
	subject          string
	identityClaims   map[string]any
	accessClaims     map[string]any // nil for an opaque access token
}

// handleLogin starts a login: a fresh session holding state, nonce and PKCE verifier, then a redirect to
// the IdP's authorization endpoint.
func (p *Provider) handleLogin(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	state, err := oauthlogin.Begin(ctx, p.options.Sessions, writer, request, p.loginKey)
	if err != nil {
		p.refuse(writer, request, auth.Outcome{Action: auth.ActionLogin, Err: fmt.Errorf("oidc: begin login: %w", err)})
		return
	}
	redirectTo(writer, p.oauth2Config.AuthCodeURL(state.State, gooidc.Nonce(state.Nonce), oauth2.S256ChallengeOption(state.Verifier)))
	p.report(ctx, auth.Outcome{Action: auth.ActionLogin, Result: auth.ResultSuccess})
}

// handleCallback finishes a login: state, code exchange, ID token, OnLogin, then a rotated session
// holding the identity and the raw ID token, and a redirect to the return path.
func (p *Provider) handleCallback(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	state, err := oauthlogin.Complete(ctx, p.options.Sessions, request, p.loginKey)
	if err != nil {
		p.refuseCallback(writer, request, err, nil)
		return
	}
	login, err := p.verifyLogin(ctx, request.URL.Query().Get("code"), state)
	if err != nil {
		p.refuseCallback(writer, request, err, nil)
		return
	}
	authenticated := p.newIdentity(login)
	identity, err := p.runOnLogin(ctx, authenticated)
	if err != nil {
		p.refuseCallback(writer, request, err, authenticated)
		return
	}
	if err := p.saveSession(ctx, writer, request, identity, login.rawIdentityToken); err != nil {
		p.refuseCallback(writer, request, err, identity)
		return
	}
	redirectTo(writer, p.options.ExternalURL+state.ReturnPath)
	p.report(ctx, auth.Outcome{Action: auth.ActionCallback, Result: auth.ResultSuccess, Identity: identity})
}

// verifyLogin exchanges code with the PKCE verifier, verifies the ID token and its nonce, checks the
// email domain and reads the access token's claims.
func (p *Provider) verifyLogin(ctx context.Context, code string, state oauthlogin.State) (verifiedLogin, error) {
	token, err := p.exchange(ctx, code, state.Verifier)
	if err != nil {
		return verifiedLogin{}, err
	}
	login, err := p.verifyIdentityToken(ctx, token, state.Nonce)
	if err != nil {
		return verifiedLogin{}, err
	}
	if err := checkEmailDomain(login.identityClaims, p.options.AllowedEmailDomains); err != nil {
		return verifiedLogin{}, err
	}
	login.accessClaims = p.accessTokenClaims(ctx, token.AccessToken)
	return login, nil
}

// exchange redeems code at the token endpoint. The IdP rejecting it is a login_failed refusal; not
// reaching the IdP is an internal failure.
func (p *Provider) exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	token, err := p.oauth2Config.Exchange(gooidc.ClientContext(ctx, p.options.HTTPClient), code, oauth2.VerifierOption(verifier))
	var retrieveError *oauth2.RetrieveError
	switch {
	case errors.As(err, &retrieveError):
		return nil, loginFailed("token exchange", dependencyError("exchange code", err))
	case err != nil:
		return nil, dependencyError("oidc: exchange code", err)
	}
	return token, nil
}

func (p *Provider) verifyIdentityToken(ctx context.Context, token *oauth2.Token, nonce string) (verifiedLogin, error) {
	rawIdentityToken, _ := token.Extra("id_token").(string)
	if rawIdentityToken == "" {
		return verifiedLogin{}, loginFailed("no ID token", nil)
	}
	identityToken, err := p.identityTokenVerifier.Verify(ctx, rawIdentityToken)
	if err != nil {
		return verifiedLogin{}, loginFailed("ID token verification", dependencyError("verify ID token", err))
	}
	if subtle.ConstantTimeCompare([]byte(identityToken.Nonce), []byte(nonce)) != 1 {
		return verifiedLogin{}, loginFailed("nonce mismatch", nil)
	}
	if identityToken.Subject == "" {
		return verifiedLogin{}, loginFailed("ID token without subject", nil)
	}
	var claims map[string]any
	if err := identityToken.Claims(&claims); err != nil {
		return verifiedLogin{}, loginFailed("ID token claims", dependencyError("decode ID token claims", err))
	}
	return verifiedLogin{rawIdentityToken: rawIdentityToken, subject: identityToken.Subject, identityClaims: claims}, nil
}

// accessTokenClaims returns the claims of a JWT access token signed by the issuer, or nil. Not every IdP
// issues JWT access tokens (Google's are opaque), so a token that does not verify only means that the
// roles and groups come from the ID token.
func (p *Provider) accessTokenClaims(ctx context.Context, rawAccessToken string) map[string]any {
	accessToken, err := p.accessTokenVerifier.Verify(ctx, rawAccessToken)
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := accessToken.Claims(&claims); err != nil {
		return nil
	}
	return claims
}

func (p *Provider) newIdentity(login verifiedLogin) *auth.Identity {
	profile := p.options.ClaimMapper(login.identityClaims)
	return &auth.Identity{
		Provider:        p.options.Name,
		Subject:         login.subject,
		Username:        profile.Username,
		Name:            profile.Name,
		Email:           profile.Email,
		Picture:         profile.Picture,
		Active:          true,
		OIDCRoles:       firstNonEmpty(realmRoles(login.accessClaims), realmRoles(login.identityClaims)),
		OIDCClientRoles: firstNonEmpty(clientRoles(login.accessClaims, p.options.ClientID), clientRoles(login.identityClaims, p.options.ClientID)),
		Groups:          firstNonEmpty(groups(login.accessClaims), groups(login.identityClaims)),
		Claims:          login.identityClaims,
	}
}

// runOnLogin returns the identity OnLogin made of identity. Its refusals keep their kind (status).
func (p *Provider) runOnLogin(ctx context.Context, identity *auth.Identity) (*auth.Identity, error) {
	if p.options.OnLogin == nil {
		return identity, nil
	}
	mapped, err := p.options.OnLogin(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("oidc: OnLogin: %w", err)
	}
	if mapped == nil {
		return nil, errors.New("oidc: OnLogin returned no identity")
	}
	return mapped, nil
}

// saveSession rotates the session (fixation defense) and stores the identity and the raw ID token in it.
func (p *Provider) saveSession(ctx context.Context, writer http.ResponseWriter, request *http.Request, identity *auth.Identity, rawIdentityToken string) error {
	current, err := p.options.Sessions.Start(ctx, writer, request)
	if err != nil {
		return fmt.Errorf("oidc: start session: %w", err)
	}
	if err := current.SaveIdentity(ctx, identity); err != nil {
		return fmt.Errorf("oidc: save identity: %w", err)
	}
	if err := current.Put(ctx, p.identityTokenKey, []byte(rawIdentityToken), p.options.Sessions.MaxAge()); err != nil {
		return fmt.Errorf("oidc: save ID token: %w", err)
	}
	return nil
}

// refuseCallback answers a failed callback: a redirect to ErrorURL?code=<code> when configured, JSON
// otherwise.
func (p *Provider) refuseCallback(writer http.ResponseWriter, request *http.Request, err error, identity *auth.Identity) {
	outcome := auth.Outcome{Action: auth.ActionCallback, Err: err, Identity: identity}
	if p.options.ErrorURL == "" {
		p.refuse(writer, request, outcome)
		return
	}
	_, response := auth.ResponseFor(err)
	redirectTo(writer, withQuery(p.options.ErrorURL, url.Values{"code": {response.Code}}))
	p.reportFailure(request.Context(), outcome)
}

// refuse answers outcome.Err as JSON and reports the outcome.
func (p *Provider) refuse(writer http.ResponseWriter, request *http.Request, outcome auth.Outcome) {
	auth.WriteError(writer, outcome.Err)
	p.reportFailure(request.Context(), outcome)
}

// reportFailure reports outcome as denied (a refusal) or error (answered with 500).
func (p *Provider) reportFailure(ctx context.Context, outcome auth.Outcome) {
	outcome.Result = auth.ResultDenied
	if status, _ := auth.ResponseFor(outcome.Err); status >= http.StatusInternalServerError {
		outcome.Result = auth.ResultError
	}
	p.report(ctx, outcome)
}

func (p *Provider) report(ctx context.Context, outcome auth.Outcome) {
	if p.options.Observer == nil {
		return
	}
	outcome.Provider = p.options.Name
	p.options.Observer(ctx, outcome)
}

func loginFailed(reason string, cause error) error {
	return &auth.Error{Kind: auth.ErrUnauthenticated, Code: "login_failed", Reason: reason, Err: cause}
}

func redirectTo(writer http.ResponseWriter, location string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Location", location)
	writer.WriteHeader(http.StatusFound)
}

// withQuery appends values to target, keeping a query target already has.
func withQuery(target string, values url.Values) string {
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return target + separator + values.Encode()
}
