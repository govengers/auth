package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/internal/failure"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/session"
)

const (
	defaultHTTPTimeout = 10 * time.Second
	// maximumDocumentBytes bounds a discovery document or JWKS; real ones are a few KiB.
	maximumDocumentBytes = 1 << 20
)

var (
	namePattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	// reservedNames are other providers' Identity.Provider or Outcome.Provider values.
	reservedNames = []string{auth.ProviderPassword, auth.ProviderGitHub, auth.ProviderAPIKey, auth.ProviderSession, auth.ProviderJWT}
	defaultScopes = []string{gooidc.ScopeOpenID, "profile", "email"}
)

// Options configure a Provider.
type Options struct {
	Name                         string          // required; [a-z0-9-]{1,32}; not "password", "github", "apikey", "session", "jwt"; becomes Identity.Provider
	Issuer                       string          // required; https, or http on a loopback host; discovery at <Issuer>/.well-known/openid-configuration
	ClientID, ClientSecret       string          // required (confidential client)
	Scopes                       []string        // default ["openid","profile","email"]; "openid" added first when missing; order kept, duplicates dropped; empty or space-containing entries are an error
	ExternalURL                  string          // required: absolute public base URL; redirect URI = ExternalURL + PathPrefix + "/callback"
	PathPrefix                   string          // default "/auth/oidc/" + Name; segments of A-Z a-z 0-9 . _ ~ -, no trailing "/", no "." or ".." segment
	PostLogoutURL                string          // default ExternalURL + "/"; path or absolute http(s) URL, no fragment; a path is made absolute with ExternalURL
	ErrorURL                     string          // optional: callback failures (refusals and code=internal) redirect to ErrorURL?code=<code> instead of answering JSON; same rules as PostLogoutURL
	ClaimMapper                  ClaimMapper     // default DefaultClaimMapper
	AllowedEmailDomains          []string        // optional: requires email_verified=true and a matching domain (ASCII, case-insensitive, exact)
	DisableIframeLogoutDetection bool            // stop treating Sec-Fetch-Dest: iframe on /logout as front-channel; a cross-site iframe load of /logout is then refused (403)
	Sessions                     *session.Store  // required; not SameSite Strict (the callback would arrive without the cookie)
	HTTPClient                   *http.Client    // default 10 s timeout; used for discovery, token exchange, JWKS; a redirect fails the call
	OnLogin                      auth.Hook       // e.g. keycloak.Client.Enrich, or an app closure calling it and then provisioning
	OnLogout                     auth.LogoutHook // runs after a session was ended by /logout or /frontchannel-logout
	Observer                     auth.Observer   // optional; one outcome per request
}

// Provider is one OpenID Connect identity provider. It is safe for concurrent use.
type Provider struct {
	options               Options
	oauth2Configuration   *oauth2.Config
	identityTokenVerifier *gooidc.IDTokenVerifier
	accessTokenVerifier   *gooidc.IDTokenVerifier
	endSessionEndpoint    string // "" when discovery has none
	loginKey              string // session key of the login state
	identityTokenKey      string // session key of the raw ID token (id_token_hint at logout)
	reporter              *failure.Reporter
}

// providerMetadata are the discovery fields go-oidc does not expose.
type providerMetadata struct {
	JWKSURI                            string   `json:"jwks_uri"`
	EndSessionEndpoint                 string   `json:"end_session_endpoint"`
	TokenEndpointAuthenticationMethods []string `json:"token_endpoint_auth_methods_supported"`
}

// New validates options and runs discovery (network I/O with ctx; fails fast). It reads
// end_session_endpoint and the token endpoint's client authentication from the provider metadata and
// refuses discovered endpoints that are not https (or http on a loopback host), like the Issuer. The
// JWKS is fetched later, on the first callback, with HTTPClient. New does not modify options, and
// changing them afterwards has no effect.
func New(ctx context.Context, options *Options) (*Provider, error) {
	resolved, err := resolveOptions(options)
	if err != nil {
		return nil, err
	}
	reporter, err := failure.NewReporter(&failure.ReporterOptions{Provider: resolved.Name, Observer: resolved.Observer, ErrorURL: resolved.ErrorURL})
	if err != nil {
		return nil, fmt.Errorf("oidc provider %q: %w", resolved.Name, err)
	}
	discovered, metadata, err := discover(ctx, resolved)
	if err != nil {
		return nil, fmt.Errorf("oidc provider %q: %w", resolved.Name, err)
	}
	return &Provider{
		options:               resolved,
		oauth2Configuration:   newOAuth2Configuration(resolved, discovered.Endpoint(), metadata),
		identityTokenVerifier: discovered.Verifier(&gooidc.Config{ClientID: resolved.ClientID}),
		// an access token is audienced at its resource server, not at this client
		accessTokenVerifier: discovered.Verifier(&gooidc.Config{SkipClientIDCheck: true}),
		endSessionEndpoint:  metadata.EndSessionEndpoint,
		loginKey:            resolved.Name + ".login",
		identityTokenKey:    resolved.Name + ".id_token",
		reporter:            reporter,
	}, nil
}

// Name returns the provider name (Identity.Provider of its users).
func (p *Provider) Name() string {
	return p.options.Name
}

// Routes returns GET {PathPrefix}/login, /callback, /logout and /frontchannel-logout.
func (p *Provider) Routes() []auth.Route {
	prefix := p.options.PathPrefix
	return []auth.Route{
		{Method: http.MethodGet, Path: prefix + "/login", Handler: http.HandlerFunc(p.handleLogin)},
		{Method: http.MethodGet, Path: prefix + "/callback", Handler: http.HandlerFunc(p.handleCallback)},
		{Method: http.MethodGet, Path: prefix + "/logout", Handler: http.HandlerFunc(p.handleLogout)},
		{Method: http.MethodGet, Path: prefix + "/frontchannel-logout", Handler: http.HandlerFunc(p.handleFrontChannelLogout)},
	}
}

// LoginURL returns ExternalURL + PathPrefix + "/login", absolute so a forward-auth redirect reaches the
// browser unchanged (session.GuardOptions.LoginURL).
func (p *Provider) LoginURL() string {
	return p.options.ExternalURL + p.options.PathPrefix + "/login"
}

func discover(ctx context.Context, options Options) (*gooidc.Provider, providerMetadata, error) {
	// ClientContext: discovery uses HTTPClient, and the provider's remote key set keeps it after ctx ends.
	discovered, err := gooidc.NewProvider(gooidc.ClientContext(ctx, withoutFreeText(options.HTTPClient)), options.Issuer)
	if err != nil {
		return nil, providerMetadata{}, dependency.Error("discover issuer", err)
	}
	var metadata providerMetadata
	if err := discovered.Claims(&metadata); err != nil {
		return nil, providerMetadata{}, dependency.Error("read provider metadata", err)
	}
	if name := insecureEndpoint(discovered.Endpoint(), metadata); name != "" {
		return nil, providerMetadata{}, fmt.Errorf("discovered %s must be an https URL, or http on a loopback host", name)
	}
	return discovered, metadata, nil
}

// insecureEndpoint names the first discovered endpoint that breaks the issuer's rule (https, or http on a
// loopback host; design D16), or returns "". The document comes from the issuer, but an IdP behind a TLS
// proxy it does not know about advertises http endpoints: the token endpoint would get the client secret
// and the code in clear text, the end-session endpoint the ID token, and the JWKS decides which tokens verify.
func insecureEndpoint(endpoint oauth2.Endpoint, metadata providerMetadata) string {
	switch {
	case !redirect.IsSecureURL(endpoint.AuthURL):
		return "authorization_endpoint"
	case !redirect.IsSecureURL(endpoint.TokenURL):
		return "token_endpoint"
	case !redirect.IsSecureURL(metadata.JWKSURI):
		return "jwks_uri"
	case metadata.EndSessionEndpoint != "" && !redirect.IsSecureURL(metadata.EndSessionEndpoint):
		return "end_session_endpoint"
	}
	return ""
}

// withoutFreeText returns a copy of client for go-oidc's discovery and JWKS requests that rebuilds every
// answer's status line from its code and keeps the body only of a 200 answer holding JSON of at most
// maximumDocumentBytes, and otherwise also its Content-Type: go-oidc copies the status line, body and
// Content-Type of a failed request into its errors, and all are the server's free text (LOG-009). The body
// of another answer is never read, and a 200 body only up to the limit, so an IdP cannot fill the memory.
// The token exchange keeps the plain client: oauth2 needs the body's error code.
func withoutFreeText(client *http.Client) *http.Client {
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	filtered := *client
	filtered.Transport = freeTextFilter{next: next}
	return &filtered
}

// freeTextFilter is the RoundTripper of withoutFreeText.
type freeTextFilter struct {
	next http.RoundTripper
}

// RoundTrip passes request on and returns the answer without its free text.
func (f freeTextFilter) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := f.next.RoundTrip(request)
	if err != nil {
		return nil, err // as it is: http.Client wraps it in a *url.Error naming the request
	}
	if response.Body == nil {
		response.Body = http.NoBody // http.Client accepts a RoundTripper's answer without one
	}
	var body []byte
	if response.StatusCode == http.StatusOK {
		body, err = io.ReadAll(io.LimitReader(response.Body, maximumDocumentBytes+1))
	}
	_ = response.Body.Close() // read as far as needed: a close error loses nothing
	if err != nil {
		return nil, fmt.Errorf("read answer of %s: %w", request.URL.Path, err)
	}
	if len(body) > maximumDocumentBytes || !json.Valid(body) {
		body = nil
		response.Header.Del("Content-Type")
	}
	response.Status = strconv.Itoa(response.StatusCode) + " " + http.StatusText(response.StatusCode)
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}

func newOAuth2Configuration(options Options, endpoint oauth2.Endpoint, metadata providerMetadata) *oauth2.Config {
	// a fixed style instead of oauth2's auto-detection, which repeats every failed exchange in the other style
	endpoint.AuthStyle = authenticationStyle(metadata.TokenEndpointAuthenticationMethods)
	return &oauth2.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  options.ExternalURL + options.PathPrefix + "/callback",
		Scopes:       options.Scopes,
	}
}

// authenticationStyle picks HTTP Basic (the OpenID Connect default when the metadata lists nothing)
// unless the token endpoint only supports client_secret_post.
func authenticationStyle(methods []string) oauth2.AuthStyle {
	if !slices.Contains(methods, "client_secret_basic") && slices.Contains(methods, "client_secret_post") {
		return oauth2.AuthStyleInParams
	}
	return oauth2.AuthStyleInHeader
}

func resolveOptions(options *Options) (Options, error) {
	if options == nil {
		return Options{}, errors.New("oidc: options are required")
	}
	if err := validateRequired(options); err != nil {
		return Options{}, fmt.Errorf("oidc provider %q: %w", options.Name, err)
	}
	resolved, err := withDefaults(*options)
	if err != nil {
		return Options{}, fmt.Errorf("oidc provider %q: %w", options.Name, err)
	}
	return resolved, nil
}

func validateRequired(options *Options) error {
	switch {
	case !namePattern.MatchString(options.Name):
		return errors.New("name must match [a-z0-9-]{1,32}")
	case slices.Contains(reservedNames, options.Name):
		return errors.New("name is reserved for another provider")
	case options.ClientID == "" || options.ClientSecret == "":
		return errors.New("client ID and client secret are required")
	case options.Sessions == nil:
		return errors.New("sessions are required")
	case options.Sessions.SameSite() == http.SameSiteStrictMode:
		return errors.New("sessions must not use SameSite Strict: the callback would arrive without the session cookie")
	case !redirect.IsSecureURL(options.Issuer):
		return errors.New("issuer must be an https URL, or http on a loopback host")
	}
	return nil
}

// withDefaults returns options with defaults applied and every kept slice copied.
func withDefaults(resolved Options) (Options, error) {
	resolved, err := withURLs(resolved)
	if err != nil {
		return Options{}, err
	}
	if resolved.Scopes, err = scopesWithOpenID(resolved.Scopes); err != nil {
		return Options{}, err
	}
	if resolved.AllowedEmailDomains, err = lowerCaseDomains(resolved.AllowedEmailDomains); err != nil {
		return Options{}, err
	}
	if resolved.ClaimMapper == nil {
		resolved.ClaimMapper = DefaultClaimMapper
	}
	if resolved.HTTPClient == nil {
		resolved.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	resolved.HTTPClient = dependency.WithoutRedirects(resolved.HTTPClient)
	return resolved, nil
}

func withURLs(resolved Options) (Options, error) {
	external, err := redirect.ExternalURL(resolved.ExternalURL)
	if err != nil {
		return Options{}, err
	}
	resolved.ExternalURL = external
	if resolved.PathPrefix == "" {
		resolved.PathPrefix = "/auth/oidc/" + resolved.Name
	}
	if !redirect.IsPathPrefix(resolved.PathPrefix) {
		return Options{}, errors.New("path prefix must start with \"/\", have no trailing \"/\" and only unreserved URL characters")
	}
	if resolved.PostLogoutURL == "" {
		resolved.PostLogoutURL = "/"
	}
	if resolved.PostLogoutURL, err = redirect.AbsoluteTarget(resolved.PostLogoutURL, external); err != nil {
		return Options{}, fmt.Errorf("post-logout URL %w", err)
	}
	if resolved.ErrorURL == "" {
		return resolved, nil
	}
	if resolved.ErrorURL, err = redirect.AbsoluteTarget(resolved.ErrorURL, external); err != nil {
		return Options{}, fmt.Errorf("error URL %w", err)
	}
	return resolved, nil
}

func scopesWithOpenID(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return slices.Clone(defaultScopes), nil
	}
	result := make([]string, 0, len(scopes)+1)
	if !slices.Contains(scopes, gooidc.ScopeOpenID) {
		result = append(result, gooidc.ScopeOpenID)
	}
	for _, scope := range scopes {
		if scope == "" || strings.ContainsFunc(scope, isSpaceOrControl) {
			return nil, errors.New("scopes must not be empty or contain spaces")
		}
		if !slices.Contains(result, scope) {
			result = append(result, scope)
		}
	}
	return result, nil
}

func lowerCaseDomains(domains []string) ([]string, error) {
	var result []string
	for _, domain := range domains {
		if domain == "" || strings.ContainsRune(domain, '@') || strings.ContainsFunc(domain, isSpaceOrControl) {
			return nil, errors.New("allowed email domains must be bare domains like example.com")
		}
		lowered, ascii := asciiLower(domain)
		if !ascii {
			return nil, fmt.Errorf("allowed email domain %q must be ASCII: write an internationalized domain in its xn-- form", domain)
		}
		result = append(result, lowered)
	}
	return result, nil
}

func isSpaceOrControl(character rune) bool {
	return character <= ' ' || character == 0x7f
}
