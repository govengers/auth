// Package keycloak enriches OIDC identities from the Keycloak Admin API: composite realm roles, client
// roles of one client, group paths and user attributes, and refuses users without the required roles or
// groups. Client.Enrich has the auth.Hook shape, so it plugs into oidc.Options.OnLogin.
//
// The client authenticates with the client credentials grant of a service account by default (the
// password grant breaks as soon as the admin user gets an OTP credential). It never logs and starts no
// goroutine.
package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/internal/tokenendpoint"
)

const (
	defaultHTTPTimeout    = 10 * time.Second
	defaultPasswordClient = "admin-cli"
	tokenRenewalMargin    = 30 * time.Second
	maximumResponseBytes  = 1 << 20
)

// errAdminTokenRefused marks an Admin API 401: the cached admin token is no longer valid.
var errAdminTokenRefused = errors.New("admin token refused")

// GrantType is how the client obtains its Admin API token.
type GrantType string

// The supported grants.
const (
	GrantTypeClientCredentials GrantType = "client_credentials" // default: the client's service account
	GrantTypePassword          GrantType = "password"           // admin-cli password grant; breaks when the user gets an OTP credential
)

// Options configure a Client.
type Options struct {
	URL                 string    // required: Keycloak base URL; https, or http on a loopback host
	Realm               string    // required: realm of the users
	AuthenticationRealm string    // realm the service account logs into; default Realm (e.g. "master" for a master admin)
	GrantType           GrantType // default GrantTypeClientCredentials
	ClientID            string    // required for client credentials; password grant default "admin-cli"
	ClientSecret        string    // required for client credentials; optional for the password grant
	Username, Password  string    // required for the password grant
	ClientRolesClientID string    // optional: clientId whose client roles become OIDCClientRoles
	RequiredRealmRoles  []string
	RequiredClientRoles []string     // needs ClientRolesClientID
	RequiredGroups      []string     // group paths ("/parent/child")
	HTTPClient          *http.Client // default 10 s timeout; a redirect fails the call
}

// Client reads users' authorization from the Keycloak Admin API. It caches its access token until 30 s
// before expiry, or until the Admin API answers 401 to it (then the next call requests a new one), and the
// client UUID of ClientRolesClientID after the first successful lookup. It is safe for concurrent use.
type Client struct {
	options      Options
	requestToken func(ctx context.Context) (*oauth2.Token, error)
	now          func() time.Time

	mutex             sync.Mutex // guards the caches below; held while a token is requested
	adminToken        string
	adminTokenRenewAt time.Time
	clientUUID        string
}

// userAuthorization is the Admin API's answer for one user.
type userAuthorization struct {
	realmRoles  []string
	clientRoles []string
	groups      []string
	attributes  map[string][]string
}

// New validates options and returns a Client; it does no I/O. It does not modify options, and changing
// them afterwards has no effect.
func New(options *Options) (*Client, error) {
	resolved, err := resolveOptions(options)
	if err != nil {
		return nil, err
	}
	return &Client{options: resolved, requestToken: newTokenRequester(resolved), now: time.Now}, nil
}

func resolveOptions(options *Options) (Options, error) {
	if options == nil {
		return Options{}, errors.New("keycloak: options are required")
	}
	resolved := *options
	resolved.URL = strings.TrimSuffix(resolved.URL, "/")
	if resolved.AuthenticationRealm == "" {
		resolved.AuthenticationRealm = resolved.Realm
	}
	if resolved.GrantType == "" {
		resolved.GrantType = GrantTypeClientCredentials
	}
	if resolved.GrantType == GrantTypePassword && resolved.ClientID == "" {
		resolved.ClientID = defaultPasswordClient
	}
	if resolved.HTTPClient == nil {
		resolved.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	resolved.HTTPClient = dependency.WithoutRedirects(resolved.HTTPClient)
	if err := validate(resolved); err != nil {
		return Options{}, fmt.Errorf("keycloak: %w", err)
	}
	resolved.RequiredRealmRoles = slices.Clone(options.RequiredRealmRoles)
	resolved.RequiredClientRoles = slices.Clone(options.RequiredClientRoles)
	resolved.RequiredGroups = slices.Clone(options.RequiredGroups)
	return resolved, nil
}

func validate(options Options) error {
	switch {
	case !redirect.IsSecureURL(options.URL) || strings.ContainsAny(options.URL, "?#"):
		return errors.New("URL must be an https URL without query, or http on a loopback host")
	case options.Realm == "":
		return errors.New("realm is required")
	case options.GrantType == GrantTypeClientCredentials && (options.ClientID == "" || options.ClientSecret == ""):
		return errors.New("client ID and client secret are required for the client credentials grant")
	case options.GrantType == GrantTypePassword && (options.Username == "" || options.Password == ""):
		return errors.New("username and password are required for the password grant")
	case options.GrantType != GrantTypeClientCredentials && options.GrantType != GrantTypePassword:
		return errors.New("grant type must be client_credentials or password")
	case len(options.RequiredClientRoles) > 0 && options.ClientRolesClientID == "":
		return errors.New("required client roles need ClientRolesClientID")
	}
	return nil
}

// newTokenRequester returns the token request of the configured grant. Credentials go in the form, as
// Keycloak's admin-cli and service accounts expect them.
func newTokenRequester(options Options) func(ctx context.Context) (*oauth2.Token, error) {
	tokenURL := options.URL + "/realms/" + url.PathEscape(options.AuthenticationRealm) + "/protocol/openid-connect/token"
	if options.GrantType == GrantTypePassword {
		configuration := &oauth2.Config{
			ClientID:     options.ClientID,
			ClientSecret: options.ClientSecret,
			Endpoint:     oauth2.Endpoint{TokenURL: tokenURL, AuthStyle: oauth2.AuthStyleInParams},
		}
		return func(ctx context.Context) (*oauth2.Token, error) {
			return configuration.PasswordCredentialsToken(ctx, options.Username, options.Password)
		}
	}
	configuration := &clientcredentials.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		TokenURL:     tokenURL,
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	return configuration.Token
}

// Enrich has the auth.Hook shape; identity.Subject is the Keycloak user ID. It returns a Clone with
// OIDCRoles (composite realm roles), OIDCClientRoles (composite roles of ClientRolesClientID, else none),
// Groups (paths) and Attributes replaced by the Admin API's answer. A missing required role or group is
// an *auth.Error{Kind: auth.ErrForbidden} whose Reason names it (never sent to the client); an API failure
// is a plain error.
func (c *Client) Enrich(ctx context.Context, identity *auth.Identity) (*auth.Identity, error) {
	if identity == nil || identity.Subject == "" {
		return nil, errors.New("keycloak: enrich: identity has no subject")
	}
	authorization, err := c.userAuthorization(ctx, identity.Subject)
	if err != nil {
		return nil, fmt.Errorf("keycloak: enrich user %s: %w", identity.Subject, err)
	}
	if err := missingRequirement(authorization, c.options); err != nil {
		return nil, err
	}
	enriched := identity.Clone()
	enriched.OIDCRoles = authorization.realmRoles
	enriched.OIDCClientRoles = authorization.clientRoles
	enriched.Groups = authorization.groups
	enriched.Attributes = authorization.attributes
	return enriched, nil
}

// userAuthorization reads the user's roles, groups and attributes with the cached admin token and drops
// that token when the Admin API refused it.
func (c *Client) userAuthorization(ctx context.Context, userID string) (userAuthorization, error) {
	accessToken, err := c.accessToken(ctx)
	if err != nil {
		return userAuthorization{}, err
	}
	authorization, err := c.readAuthorization(ctx, accessToken, userID)
	if errors.Is(err, errAdminTokenRefused) {
		c.dropAdminToken(accessToken)
	}
	return authorization, err
}

func (c *Client) readAuthorization(ctx context.Context, accessToken, userID string) (userAuthorization, error) {
	user := c.adminURL() + "/users/" + url.PathEscape(userID)
	var authorization userAuthorization
	var err error
	if authorization.realmRoles, err = c.roleNames(ctx, accessToken, user+"/role-mappings/realm/composite"); err != nil {
		return userAuthorization{}, err
	}
	if authorization.clientRoles, err = c.clientRoleNames(ctx, accessToken, user); err != nil {
		return userAuthorization{}, err
	}
	if authorization.groups, err = c.groupPaths(ctx, accessToken, user+"/groups"); err != nil {
		return userAuthorization{}, err
	}
	if authorization.attributes, err = c.attributes(ctx, accessToken, user); err != nil {
		return userAuthorization{}, err
	}
	return authorization, nil
}

// accessToken returns the cached Admin API token, requesting a new one from 30 s before its expiry or once
// the Admin API answered 401 to it (dropAdminToken).
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// ponytail: the token request runs under the lock, so concurrent logins wait for it (at most
	// HTTPClient's timeout, once per token lifetime); use a request-in-flight flag if that ever matters.
	if c.adminToken != "" && c.now().Before(c.adminTokenRenewAt) {
		return c.adminToken, nil
	}
	token, err := c.requestToken(context.WithValue(ctx, oauth2.HTTPClient, c.options.HTTPClient))
	if err != nil {
		return "", tokenendpoint.Error("request admin token", err)
	}
	// oauth2 turns expires_in into Expiry with time.Now (the client credentials grant keeps no ExpiresIn),
	// so the remaining lifetime is read off the wall clock on purpose and only the deadline uses c.now;
	// without expires_in Expiry is zero and the token is not reused.
	lifetime := time.Until(token.Expiry)
	c.adminToken = token.AccessToken
	c.adminTokenRenewAt = c.now().Add(lifetime - tokenRenewalMargin)
	return c.adminToken, nil
}

// dropAdminToken forgets accessToken after the Admin API refused it (Keycloak revokes tokens before their
// expiry), so the next Enrich requests a new one instead of failing until the renewal time. A token
// renewed meanwhile stays.
func (c *Client) dropAdminToken(accessToken string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.adminToken == accessToken {
		c.adminToken = ""
	}
}

func (c *Client) clientRoleNames(ctx context.Context, accessToken, user string) ([]string, error) {
	if c.options.ClientRolesClientID == "" {
		return nil, nil
	}
	clientUUID, err := c.resolveClientUUID(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	return c.roleNames(ctx, accessToken, user+"/role-mappings/clients/"+url.PathEscape(clientUUID)+"/composite")
}

// resolveClientUUID returns the internal ID of ClientRolesClientID, cached after the first success; a
// failed lookup is repeated by the next login.
func (c *Client) resolveClientUUID(ctx context.Context, accessToken string) (string, error) {
	c.mutex.Lock()
	cached := c.clientUUID
	c.mutex.Unlock()
	if cached != "" {
		return cached, nil
	}
	var clients []struct {
		ID string `json:"id"`
	}
	query := url.Values{"clientId": {c.options.ClientRolesClientID}}
	if err := c.getJSON(ctx, accessToken, c.adminURL()+"/clients?"+query.Encode(), &clients); err != nil {
		return "", err
	}
	if len(clients) == 0 || clients[0].ID == "" {
		return "", fmt.Errorf("client %q not found in realm %q", c.options.ClientRolesClientID, c.options.Realm)
	}
	c.mutex.Lock()
	c.clientUUID = clients[0].ID
	c.mutex.Unlock()
	return clients[0].ID, nil
}

func (c *Client) roleNames(ctx context.Context, accessToken, endpoint string) ([]string, error) {
	var roles []struct {
		Name string `json:"name"`
	}
	if err := c.getJSON(ctx, accessToken, endpoint, &roles); err != nil {
		return nil, err
	}
	var names []string
	for _, role := range roles {
		names = append(names, role.Name)
	}
	return names, nil
}

func (c *Client) groupPaths(ctx context.Context, accessToken, endpoint string) ([]string, error) {
	var groups []struct {
		Path string `json:"path"`
	}
	if err := c.getJSON(ctx, accessToken, endpoint, &groups); err != nil {
		return nil, err
	}
	var paths []string
	for _, group := range groups {
		paths = append(paths, group.Path)
	}
	return paths, nil
}

func (c *Client) attributes(ctx context.Context, accessToken, user string) (map[string][]string, error) {
	var representation struct {
		Attributes map[string][]string `json:"attributes"`
	}
	if err := c.getJSON(ctx, accessToken, user, &representation); err != nil {
		return nil, err
	}
	return representation.Attributes, nil
}

func (c *Client) getJSON(ctx context.Context, accessToken, endpoint string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build admin API request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	response, err := c.options.HTTPClient.Do(request)
	if err != nil {
		return dependency.Error("call admin API", err)
	}
	defer func() { _ = response.Body.Close() }() // read-only response, close error carries no information
	if response.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("admin API %s answered HTTP %d: %w", request.URL.Path, response.StatusCode, errAdminTokenRefused)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("admin API %s answered HTTP %d", request.URL.Path, response.StatusCode) // the reason phrase is the server's free text
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumResponseBytes)).Decode(target); err != nil {
		return dependency.Error("decode admin API answer of "+request.URL.Path, err)
	}
	return nil
}

func (c *Client) adminURL() string {
	return c.options.URL + "/admin/realms/" + url.PathEscape(c.options.Realm)
}

// missingRequirement refuses a user without every required realm role, client role and group.
func missingRequirement(authorization userAuthorization, options Options) error {
	requirements := []struct {
		kind     string
		required []string
		granted  []string
	}{
		{kind: "realm role", required: options.RequiredRealmRoles, granted: authorization.realmRoles},
		{kind: "client role", required: options.RequiredClientRoles, granted: authorization.clientRoles},
		{kind: "group", required: options.RequiredGroups, granted: authorization.groups},
	}
	for _, requirement := range requirements {
		for _, name := range requirement.required {
			if !slices.Contains(requirement.granted, name) {
				return &auth.Error{Kind: auth.ErrForbidden, Reason: "missing " + requirement.kind + " " + name}
			}
		}
	}
	return nil
}
