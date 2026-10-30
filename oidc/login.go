package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/internal/hook"
	"github.com/govengers/auth/internal/oauthlogin"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/internal/tokenendpoint"
)

// verifiedLogin is what a callback learned from the IdP before any hook ran.
type verifiedLogin struct {
	rawIdentityToken string
	subject          string
	identityClaims   map[string]any
	accessClaims     map[string]any // nil for an opaque access token
}

// handleLogin starts a login: state, nonce and PKCE verifier in the session (oauthlogin.Begin keeps one
// holding a live identity, else starts a new one), then a redirect to the IdP's authorization endpoint.
func (p *Provider) handleLogin(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	state, err := oauthlogin.Begin(ctx, p.options.Sessions, writer, request, p.loginKey)
	if err != nil {
		p.reporter.Refuse(ctx, writer, auth.Outcome{Action: auth.ActionLogin, Err: fmt.Errorf("oidc: begin login: %w", err)})
		return
	}
	redirect.To(writer, p.oauth2Configuration.AuthCodeURL(state.State, gooidc.Nonce(state.Nonce), oauth2.S256ChallengeOption(state.Verifier)))
	p.reporter.Report(ctx, auth.Outcome{Action: auth.ActionLogin, Result: auth.ResultSuccess})
}

// handleCallback finishes a login: state, code exchange, ID token, OnLogin, then a rotated session
// holding the identity and the raw ID token, and a redirect to the return path.
func (p *Provider) handleCallback(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	state, err := oauthlogin.Complete(ctx, p.options.Sessions, request, p.loginKey)
	if err != nil {
		p.reporter.RefuseCallback(ctx, writer, auth.Outcome{Action: auth.ActionCallback, Err: err})
		return
	}
	login, err := p.verifyLogin(ctx, request.URL.Query().Get("code"), state)
	if err != nil {
		p.reporter.RefuseCallback(ctx, writer, auth.Outcome{Action: auth.ActionCallback, Err: err})
		return
	}
	authenticated := p.newIdentity(login)
	identity, err := hook.RunOnLogin(ctx, p.options.OnLogin, authenticated)
	if err != nil {
		p.reporter.RefuseCallback(ctx, writer, auth.Outcome{Action: auth.ActionCallback, Err: err, Identity: authenticated})
		return
	}
	if err := p.saveSession(ctx, writer, request, identity, login.rawIdentityToken); err != nil {
		p.reporter.RefuseCallback(ctx, writer, auth.Outcome{Action: auth.ActionCallback, Err: err, Identity: identity})
		return
	}
	redirect.To(writer, p.options.ExternalURL+state.ReturnPath)
	p.reporter.Report(ctx, auth.Outcome{Action: auth.ActionCallback, Result: auth.ResultSuccess, Identity: identity})
}

// verifyLogin exchanges code with the PKCE verifier, verifies the ID token and its nonce, checks the
// email domain and reads the claims of an access token issued to the same subject.
func (p *Provider) verifyLogin(ctx context.Context, code string, state oauthlogin.State) (verifiedLogin, error) {
	token, err := p.exchange(ctx, code, state.Verifier)
	if err != nil {
		return verifiedLogin{}, err
	}
	login, err := p.verifyIdentityToken(ctx, token, state.Nonce)
	if err != nil {
		return verifiedLogin{}, err
	}
	if err := checkEmailDomain(login.identityClaims, p.options.AllowedEmailDomains, p.options.Issuer == GoogleIssuer); err != nil {
		return verifiedLogin{}, err
	}
	login.accessClaims = p.accessTokenClaims(ctx, token.AccessToken, login.subject)
	return login, nil
}

// exchange redeems code at the token endpoint. The IdP rejecting it (an error answer below 500) is a
// login_failed refusal; a 5xx answer or not reaching the IdP is an internal failure.
func (p *Provider) exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	token, err := p.oauth2Configuration.Exchange(gooidc.ClientContext(ctx, p.options.HTTPClient), code, oauth2.VerifierOption(verifier))
	switch {
	case tokenendpoint.Refused(err):
		return nil, loginFailed("token exchange", tokenendpoint.Error("oidc: exchange code", err))
	case err != nil:
		return nil, tokenendpoint.Error("oidc: exchange code", err)
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
		return verifiedLogin{}, loginFailed(identityTokenRefusal(err), ctx.Err())
	}
	if subtle.ConstantTimeCompare([]byte(identityToken.Nonce), []byte(nonce)) != 1 {
		return verifiedLogin{}, loginFailed("nonce mismatch", nil)
	}
	if identityToken.Subject == "" {
		return verifiedLogin{}, loginFailed("ID token without subject", nil)
	}
	var claims map[string]any
	if err := identityToken.Claims(&claims); err != nil {
		return verifiedLogin{}, loginFailed("ID token claims", dependency.Error("decode ID token claims", err))
	}
	return verifiedLogin{rawIdentityToken: rawIdentityToken, subject: identityToken.Subject, identityClaims: claims}, nil
}

// identityTokenRefusal names why go-oidc refused an ID token with a fixed text: its message quotes the
// token's header and claims and flattens the JWKS request's error with the server's text (LOG-009).
// ponytail: a JWKS outage reads like an invalid token; wrap the key set to tell them apart if that matters.
func identityTokenRefusal(err error) string {
	var expired *gooidc.TokenExpiredError
	if errors.As(err, &expired) {
		return "ID token expired"
	}
	return "ID token verification"
}

// accessTokenClaims returns the claims of a JWT access token signed by the issuer for subject (the ID
// token's sub), or nil. Not every IdP issues JWT access tokens (Google's are opaque), so a token that does
// not verify only means that the roles and groups come from the ID token. A token for another subject is
// ignored the same way: its roles are not this user's.
func (p *Provider) accessTokenClaims(ctx context.Context, rawAccessToken, subject string) map[string]any {
	accessToken, err := p.accessTokenVerifier.Verify(ctx, rawAccessToken)
	if err != nil || accessToken.Subject != subject {
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

// saveSession rotates the session (fixation defense) and stores the raw ID token and then the identity in
// it: the identity authenticates the session, so a failed write leaves none behind the 500.
func (p *Provider) saveSession(ctx context.Context, writer http.ResponseWriter, request *http.Request, identity *auth.Identity, rawIdentityToken string) error {
	current, err := p.options.Sessions.Start(ctx, writer, request)
	if err != nil {
		return fmt.Errorf("oidc: start session: %w", err)
	}
	if err := current.Put(ctx, p.identityTokenKey, []byte(rawIdentityToken), p.options.Sessions.MaximumAge()); err != nil {
		return fmt.Errorf("oidc: save ID token: %w", err)
	}
	if err := current.SaveIdentity(ctx, identity); err != nil {
		return fmt.Errorf("oidc: save identity: %w", err)
	}
	return nil
}

func loginFailed(reason string, cause error) error {
	return &auth.Error{Kind: auth.ErrUnauthenticated, Code: oauthlogin.CodeLoginFailed, Reason: reason, Err: cause}
}
