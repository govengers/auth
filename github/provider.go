package github

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/session"
)

const (
	providerName        = "github"
	loginKey            = providerName + ".login"
	tokenKey            = providerName + ".token"
	defaultPathPrefix   = "/auth/github"
	defaultAuthorizeURL = "https://github.com/login/oauth/authorize"
	defaultTokenURL     = "https://github.com/login/oauth/access_token" //nolint:gosec // G101: an endpoint URL, not a credential
	defaultAPIURL       = "https://api.github.com"
	defaultTimeout      = 10 * time.Second
)

// pathPrefixPattern keeps the prefix a plain path: no trailing "/", no query, no ServeMux wildcards.
var pathPrefixPattern = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)

// Options configure a Provider.
type Options struct {
	ClientID, ClientSecret string          // required: the GitHub OAuth app
	Scopes                 []string        // default ["read:org"]
	AuthorizeURL           string          // default "https://github.com/login/oauth/authorize"
	TokenURL               string          // default "https://github.com/login/oauth/access_token"
	APIURL                 string          // default "https://api.github.com"; GHE e.g. https://ghe.example.com/api/v3
	ExternalURL            string          // required: absolute public base URL; redirect URI = ExternalURL + PathPrefix + "/callback"
	PathPrefix             string          // default "/auth/github"
	PostLogoutURL          string          // default ExternalURL + "/"; path or absolute http(s) URL, no fragment; a path is made absolute with ExternalURL
	ErrorURL               string          // optional: callback failures (refusals and code=internal) redirect to ErrorURL?code=<code> instead of answering JSON; same rules as PostLogoutURL
	AllowedTeams           []string        // required, at least one, "org/team-slug", case-insensitive
	AdminTeams             []string        // members get auth.RoleAdmin (they still need an AllowedTeams membership)
	RelevantTeams          []string        // extra teams kept in Identity.Teams
	Sessions               *session.Store  // required
	HTTPClient             *http.Client    // default 10 s timeout; token exchange, GitHub API, revocation
	OnLogin                auth.Hook       // optional: maps or refuses the identity before the session exists
	OnLogout               auth.LogoutHook // optional
	Observer               auth.Observer   // optional
}

// Provider is the GitHub OAuth provider. AuthorizeURL, TokenURL and APIURL must use https, except on
// loopback hosts (localhost, 127.0.0.0/8, ::1). It is safe for concurrent use.
type Provider struct {
	options Options // resolved copy: defaults applied, slices cloned, team lists lower-cased
	oauth   *oauth2.Config
	api     *url.URL // parsed APIURL: the only scheme and host the session's token is sent to
}

// New validates options and returns a Provider working on a copy of them: the caller's struct and
// slices are never modified, and changing them afterwards has no effect. New does no I/O.
func New(options *Options) (*Provider, error) {
	if options == nil {
		return nil, errors.New("github: options are required")
	}
	resolved, err := resolveOptions(*options)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	api, err := url.Parse(resolved.APIURL)
	if err != nil {
		return nil, fmt.Errorf("github: APIURL: %w", err)
	}
	return &Provider{options: resolved, oauth: oauthConfig(resolved), api: api}, nil
}

// Name returns "github", the Identity.Provider of every identity this provider creates.
func (p *Provider) Name() string {
	return providerName
}

// LoginURL returns ExternalURL + PathPrefix + "/login", the absolute URL that starts a login (use it as
// session.GuardOptions.LoginURL).
func (p *Provider) LoginURL() string {
	return p.options.ExternalURL + p.options.PathPrefix + "/login"
}

func resolveOptions(options Options) (Options, error) {
	if options.ClientID == "" || options.ClientSecret == "" || options.Sessions == nil {
		return Options{}, errors.New("ClientID, ClientSecret and Sessions are required")
	}
	externalURL, err := redirect.ExternalURL(options.ExternalURL)
	if err != nil {
		return Options{}, fmt.Errorf("ExternalURL: %w", err)
	}
	options.ExternalURL = externalURL
	options, err = withURLs(withDefaults(options))
	if err != nil {
		return Options{}, err
	}
	return withParsedTeams(options)
}

func withDefaults(options Options) Options {
	if len(options.Scopes) == 0 {
		options.Scopes = []string{"read:org"}
	}
	options.Scopes = slices.Clone(options.Scopes)
	options.AuthorizeURL = cmp.Or(options.AuthorizeURL, defaultAuthorizeURL)
	options.TokenURL = cmp.Or(options.TokenURL, defaultTokenURL)
	options.APIURL = strings.TrimSuffix(cmp.Or(options.APIURL, defaultAPIURL), "/")
	options.PathPrefix = cmp.Or(options.PathPrefix, defaultPathPrefix)
	options.PostLogoutURL = cmp.Or(options.PostLogoutURL, "/")
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: defaultTimeout}
	}
	return options
}

// withURLs validates the endpoints and the path prefix and makes PostLogoutURL and ErrorURL absolute.
func withURLs(options Options) (Options, error) {
	for _, endpoint := range []struct{ field, value string }{
		{"AuthorizeURL", options.AuthorizeURL}, {"TokenURL", options.TokenURL}, {"APIURL", options.APIURL},
	} {
		if !redirect.IsSecureURL(endpoint.value) {
			return Options{}, fmt.Errorf("%s must be an absolute https URL without user info (http only on a loopback host)", endpoint.field)
		}
	}
	if !pathPrefixPattern.MatchString(options.PathPrefix) {
		return Options{}, errors.New("PathPrefix must be a path like \"/auth/github\" without a trailing \"/\"")
	}
	var err error
	if options.PostLogoutURL, err = redirect.AbsoluteTarget(options.PostLogoutURL, options.ExternalURL); err != nil {
		return Options{}, fmt.Errorf("PostLogoutURL %w", err)
	}
	if options.ErrorURL == "" {
		return options, nil
	}
	if options.ErrorURL, err = redirect.AbsoluteTarget(options.ErrorURL, options.ExternalURL); err != nil {
		return Options{}, fmt.Errorf("ErrorURL %w", err)
	}
	return options, nil
}

// withParsedTeams replaces the three team lists by validated, lower-cased copies.
func withParsedTeams(options Options) (Options, error) {
	if len(options.AllowedTeams) == 0 {
		return Options{}, errors.New("AllowedTeams needs at least one \"org/team-slug\"")
	}
	var err error
	if options.AllowedTeams, err = parseTeams("AllowedTeams", options.AllowedTeams); err != nil {
		return Options{}, err
	}
	if options.AdminTeams, err = parseTeams("AdminTeams", options.AdminTeams); err != nil {
		return Options{}, err
	}
	if options.RelevantTeams, err = parseTeams("RelevantTeams", options.RelevantTeams); err != nil {
		return Options{}, err
	}
	return options, nil
}

func oauthConfig(options Options) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   options.AuthorizeURL,
			TokenURL:  options.TokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: options.ExternalURL + options.PathPrefix + "/callback",
		Scopes:      options.Scopes,
	}
}
