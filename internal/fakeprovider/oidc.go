package fakeprovider

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tokenLifetime    = 5 * time.Minute
	maximumFormBytes = 1 << 16
	defaultSubject   = "fake-user"
	signingKeyBits   = 2048
)

// oauthErrorCode is an OAuth error code (RFC 6749 4.1.2.1 and 5.2).
type oauthErrorCode string

const (
	invalidRequest       oauthErrorCode = "invalid_request"
	invalidClient        oauthErrorCode = "invalid_client"
	invalidGrant         oauthErrorCode = "invalid_grant"
	unsupportedGrantType oauthErrorCode = "unsupported_grant_type"
)

// OIDCUser is the one user the fake issuer logs in. With a Keycloak realm the Admin API answers with
// the same roles and groups the access token carries.
type OIDCUser struct {
	Subject           string              // ID token sub and Keycloak user ID; default "fake-user"
	PreferredUsername string              // preferred_username claim
	Name              string              // name claim
	Email             string              // email claim
	EmailVerified     bool                // email_verified claim
	Picture           string              // picture claim
	SessionID         string              // sid claim of the ID token; omitted when empty
	RealmRoles        []string            // access token realm_access.roles; Keycloak composite realm roles
	ClientRoles       []string            // access token resource_access.<ClientID>.roles; Keycloak composite roles of client ClientID
	Groups            []string            // access token groups; Keycloak group paths
	Attributes        map[string][]string // Keycloak user attributes
}

// OIDCOptions configures the fake issuer. Faults (the bool fields after User) make every token
// response broken in one specific way; TokenAnswer replaces the token endpoint altogether.
type OIDCOptions struct {
	IssuerURL              string   // required by NewOIDCHandler, set by StartOIDC: the iss claim; endpoints are served below its path
	ClientID               string   // required
	ClientSecret           string   // required; accepted by HTTP Basic and in the form
	RedirectURIs           []string // registered redirect URIs; empty accepts any
	PostLogoutRedirectURIs []string // registered post-logout redirect URIs; empty accepts any
	User                   OIDCUser

	OmitEndSessionEndpoint bool // discovery without end_session_endpoint
	OmitIDToken            bool // token response without id_token
	OpaqueAccessToken      bool // a random access token instead of a JWT, as Google issues
	WrongNonce             bool // the ID token carries another nonce than the authorize request
	BadSignature           bool // ID and access token signatures do not verify
	ExpiredIDToken         bool // the ID token expired a minute ago

	TokenAnswer http.Handler // when set, answers every /token request in place of the fake: an IdP's error or broken answers

	KeycloakRealm               string // when set, also serves the Keycloak token endpoint and Admin API of this realm (keycloak.go)
	KeycloakAuthenticationRealm string // realm whose token endpoint issues admin tokens; default KeycloakRealm
	KeycloakClientID            string // service account client for the client credentials grant
	KeycloakClientSecret        string
	KeycloakUsername            string // admin user for the password grant
	KeycloakPassword            string
}

// OIDCHandler is the fake issuer as an http.Handler. It serves, below the IssuerURL path:
// /.well-known/openid-configuration, /jwks, /authorize (auto-approves User: redirects to redirect_uri
// with code and state; a request without state, nonce or S256 code challenge gets error=invalid_request,
// an unknown client_id or unregistered redirect_uri a 400 page), /token (client secret, single-use code,
// redirect_uri and PKCE S256 checked; ID token with the authorize nonce and a JWT access token, RS256)
// and /end_session (records id_token_hint, redirects to a registered post_logout_redirect_uri with
// state, else a plain page). It is safe for concurrent use.
type OIDCHandler struct {
	options     OIDCOptions
	endpointURL string // IssuerURL without a trailing "/"
	key         *rsa.PrivateKey
	keyID       string
	serveMux    *http.ServeMux

	mutex                 sync.Mutex
	codes                 map[string]authorizationGrant
	adminTokens           map[string]bool
	identityTokenHints    []string
	keycloakTokenRequests int
	keycloakClientLookups int
}

type authorizationGrant struct {
	nonce       string
	challenge   string
	redirectURI string
}

// NewOIDCHandler returns a fake issuer with a fresh RSA signing key. It keeps a copy of options:
// changing them afterwards has no effect.
func NewOIDCHandler(options *OIDCOptions) (*OIDCHandler, error) {
	if options == nil || options.ClientID == "" || options.ClientSecret == "" {
		return nil, errors.New("fakeprovider: ClientID and ClientSecret are required")
	}
	issuer, err := url.Parse(options.IssuerURL)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return nil, errors.New("fakeprovider: IssuerURL must be an absolute URL")
	}
	key, err := rsa.GenerateKey(rand.Reader, signingKeyBits)
	if err != nil {
		return nil, fmt.Errorf("fakeprovider: generate signing key: %w", err)
	}
	resolved := *options
	resolved.RedirectURIs = slices.Clone(options.RedirectURIs)
	resolved.PostLogoutRedirectURIs = slices.Clone(options.PostLogoutRedirectURIs)
	resolved.User = cloneUser(options.User)
	if resolved.User.Subject == "" {
		resolved.User.Subject = defaultSubject
	}
	if resolved.KeycloakAuthenticationRealm == "" {
		resolved.KeycloakAuthenticationRealm = resolved.KeycloakRealm
	}
	handler := &OIDCHandler{
		options:     resolved,
		endpointURL: strings.TrimSuffix(resolved.IssuerURL, "/"),
		key:         key,
		keyID:       rand.Text(),
		codes:       map[string]authorizationGrant{},
		adminTokens: map[string]bool{},
	}
	handler.serveMux = handler.routes(strings.TrimSuffix(issuer.Path, "/"))
	return handler, nil
}

// cloneUser copies the slices and maps of user, so the caller's options cannot change a running issuer.
func cloneUser(user OIDCUser) OIDCUser {
	user.RealmRoles = slices.Clone(user.RealmRoles)
	user.ClientRoles = slices.Clone(user.ClientRoles)
	user.Groups = slices.Clone(user.Groups)
	user.Attributes = maps.Clone(user.Attributes)
	for name, values := range user.Attributes {
		user.Attributes[name] = slices.Clone(values)
	}
	return user
}

func (h *OIDCHandler) routes(issuerPath string) *http.ServeMux {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("GET "+issuerPath+"/.well-known/openid-configuration", h.discovery)
	serveMux.HandleFunc("GET "+issuerPath+"/jwks", h.jwks)
	serveMux.HandleFunc("GET "+issuerPath+"/authorize", h.authorize)
	serveMux.HandleFunc("POST "+issuerPath+"/token", h.token)
	serveMux.HandleFunc("GET "+issuerPath+"/end_session", h.endSession)
	if h.options.KeycloakRealm != "" {
		h.registerKeycloakRoutes(serveMux)
	}
	return serveMux
}

// ServeHTTP serves the issuer's endpoints.
func (h *OIDCHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.serveMux.ServeHTTP(writer, request)
}

// IssuerURL returns the issuer as configured: the iss claim and the discovery issuer.
func (h *OIDCHandler) IssuerURL() string {
	return h.options.IssuerURL
}

// IDTokenHints returns the id_token_hint values /end_session received, oldest first.
func (h *OIDCHandler) IDTokenHints() []string {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return slices.Clone(h.identityTokenHints)
}

// OIDCServer is a fake issuer on an httptest server.
type OIDCServer struct {
	*OIDCHandler
	url string
}

// StartOIDC serves a fake issuer on a loopback httptest server until the test ends. It sets IssuerURL to
// the server URL, or to <server URL>/realms/<KeycloakRealm> when a Keycloak realm is configured (the
// Keycloak layout). Construction errors fail the test.
func StartOIDC(tb testing.TB, options OIDCOptions) *OIDCServer {
	tb.Helper()
	server := httptest.NewUnstartedServer(nil)
	serverURL := "http://" + server.Listener.Addr().String()
	options.IssuerURL = serverURL
	if options.KeycloakRealm != "" {
		options.IssuerURL = serverURL + "/realms/" + options.KeycloakRealm
	}
	handler, err := NewOIDCHandler(&options)
	if err != nil {
		server.Close()
		tb.Fatalf("start fake OIDC issuer: %v", err)
	}
	server.Config.Handler = handler
	server.Start()
	tb.Cleanup(server.Close)
	return &OIDCServer{OIDCHandler: handler, url: serverURL}
}

// URL returns the server's base URL: the Keycloak URL when a Keycloak realm is configured.
func (s *OIDCServer) URL() string {
	return s.url
}

func (h *OIDCHandler) discovery(writer http.ResponseWriter, _ *http.Request) {
	document := map[string]any{
		"issuer":                                h.options.IssuerURL,
		"authorization_endpoint":                h.endpointURL + "/authorize",
		"token_endpoint":                        h.endpointURL + "/token",
		"jwks_uri":                              h.endpointURL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	}
	if !h.options.OmitEndSessionEndpoint {
		document["end_session_endpoint"] = h.endpointURL + "/end_session"
	}
	writeJSON(writer, http.StatusOK, document)
}

func (h *OIDCHandler) jwks(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": h.keyID,
		"n": base64.RawURLEncoding.EncodeToString(h.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(h.key.E)).Bytes()),
	}}})
}

func (h *OIDCHandler) authorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	redirectURI := query.Get("redirect_uri")
	if query.Get("client_id") != h.options.ClientID || !registered(h.options.RedirectURIs, redirectURI) {
		http.Error(writer, "unknown client_id or unregistered redirect_uri", http.StatusBadRequest) // never redirect to it
		return
	}
	if problem := authorizeProblem(query); problem != "" {
		redirectWith(writer, request, redirectURI, url.Values{"error": {string(invalidRequest)}, "error_description": {problem}, "state": {query.Get("state")}})
		return
	}
	code := h.issueCode(authorizationGrant{nonce: query.Get("nonce"), challenge: query.Get("code_challenge"), redirectURI: redirectURI})
	redirectWith(writer, request, redirectURI, url.Values{"code": {code}, "state": {query.Get("state")}})
}

// issueCode returns a new authorization code the token endpoint redeems once for grant.
func (h *OIDCHandler) issueCode(grant authorizationGrant) string {
	code := rand.Text()
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.codes[code] = grant
	return code
}

// authorizeProblem names what a strict client must not omit, or returns "".
func authorizeProblem(query url.Values) string {
	switch {
	case query.Get("response_type") != "code":
		return "response_type must be code"
	case !slices.Contains(strings.Fields(query.Get("scope")), "openid"):
		return "scope must contain openid"
	case query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256":
		return "PKCE with S256 is required"
	case query.Get("state") == "":
		return "state is required"
	case query.Get("nonce") == "":
		return "nonce is required"
	default:
		return ""
	}
}

func (h *OIDCHandler) token(writer http.ResponseWriter, request *http.Request) {
	if h.options.TokenAnswer != nil {
		h.options.TokenAnswer.ServeHTTP(writer, request)
		return
	}
	form, err := readForm(writer, request)
	if err != nil {
		oauthError(writer, http.StatusBadRequest, invalidRequest)
		return
	}
	clientID, clientSecret := clientCredentials(request, form)
	if !matches(clientID, h.options.ClientID) || !matches(clientSecret, h.options.ClientSecret) {
		oauthError(writer, http.StatusUnauthorized, invalidClient)
		return
	}
	if form.Get("grant_type") != "authorization_code" {
		oauthError(writer, http.StatusBadRequest, unsupportedGrantType)
		return
	}
	grant, found := h.takeCode(form.Get("code"))
	switch {
	case !found:
		oauthError(writer, http.StatusBadRequest, invalidGrant) // unknown or reused code
	case grant.redirectURI != form.Get("redirect_uri"):
		oauthError(writer, http.StatusBadRequest, invalidGrant)
	case challengeOf(form.Get("code_verifier")) != grant.challenge:
		oauthError(writer, http.StatusBadRequest, invalidGrant) // PKCE verification failed
	default:
		h.issueTokens(writer, grant)
	}
}

// takeCode returns the grant of code and forgets it: a code works once.
func (h *OIDCHandler) takeCode(code string) (authorizationGrant, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	grant, found := h.codes[code]
	delete(h.codes, code)
	return grant, found
}

func (h *OIDCHandler) issueTokens(writer http.ResponseWriter, grant authorizationGrant) {
	now := time.Now()
	response := map[string]any{"token_type": "Bearer", "expires_in": int(tokenLifetime.Seconds()), "scope": "openid profile email"}
	accessToken, err := h.accessToken(now)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	response["access_token"] = accessToken
	if !h.options.OmitIDToken {
		identityToken, err := h.sign(h.identityClaims(grant, now))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		response["id_token"] = identityToken
	}
	writeJSON(writer, http.StatusOK, response)
}

func (h *OIDCHandler) identityClaims(grant authorizationGrant, now time.Time) map[string]any {
	user := h.options.User
	claims := map[string]any{
		"iss": h.options.IssuerURL, "sub": user.Subject, "aud": h.options.ClientID, "azp": h.options.ClientID,
		"iat": now.Unix(), "auth_time": now.Unix(), "exp": now.Add(tokenLifetime).Unix(), "nonce": grant.nonce,
		"preferred_username": user.PreferredUsername, "name": user.Name, "email": user.Email,
		"email_verified": user.EmailVerified, "picture": user.Picture,
	}
	if user.SessionID != "" {
		claims["sid"] = user.SessionID
	}
	if h.options.WrongNonce {
		claims["nonce"] = "not-the-nonce-you-sent"
	}
	if h.options.ExpiredIDToken {
		claims["exp"] = now.Add(-time.Minute).Unix()
	}
	return claims
}

// accessToken returns a Keycloak-shaped JWT access token (audience "account", not the client), or an
// opaque one when OpaqueAccessToken is set.
func (h *OIDCHandler) accessToken(now time.Time) (string, error) {
	if h.options.OpaqueAccessToken {
		return rand.Text(), nil
	}
	user := h.options.User
	return h.sign(map[string]any{
		"iss": h.options.IssuerURL, "sub": user.Subject, "aud": "account", "azp": h.options.ClientID,
		"iat": now.Unix(), "exp": now.Add(tokenLifetime).Unix(), "scope": "openid profile email",
		"realm_access":    map[string]any{"roles": nonNil(user.RealmRoles)},
		"resource_access": map[string]any{h.options.ClientID: map[string]any{"roles": nonNil(user.ClientRoles)}},
		"groups":          nonNil(user.Groups),
	})
}

func (h *OIDCHandler) endSession(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if hint := query.Get("id_token_hint"); hint != "" {
		h.recordTokenHint(hint)
	}
	target := query.Get("post_logout_redirect_uri")
	if target == "" || !registered(h.options.PostLogoutRedirectURIs, target) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(writer, "logged out") // the client hung up: nothing left to do
		return
	}
	values := url.Values{}
	if state := query.Get("state"); state != "" {
		values.Set("state", state)
	}
	redirectWith(writer, request, target, values)
}

func (h *OIDCHandler) recordTokenHint(hint string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.identityTokenHints = append(h.identityTokenHints, hint)
}

// sign returns a compact RS256 JWT. With BadSignature the last signature bit is flipped.
func (h *OIDCHandler) sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": h.keyID})
	if err != nil {
		return "", fmt.Errorf("fakeprovider: encode header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("fakeprovider: encode claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("fakeprovider: sign: %w", err)
	}
	if h.options.BadSignature {
		signature[len(signature)-1] ^= 1
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func registered(uris []string, uri string) bool {
	return len(uris) == 0 || slices.Contains(uris, uri)
}

func readForm(writer http.ResponseWriter, request *http.Request) (url.Values, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		return nil, fmt.Errorf("fakeprovider: read form: %w", err)
	}
	return request.PostForm, nil
}

// clientCredentials reads the client by HTTP Basic (form-encoded, RFC 6749 2.3.1) or from the form.
func clientCredentials(request *http.Request, form url.Values) (clientID, clientSecret string) {
	encodedID, encodedSecret, basic := request.BasicAuth()
	if !basic {
		return form.Get("client_id"), form.Get("client_secret")
	}
	clientID, idError := url.QueryUnescape(encodedID)
	clientSecret, secretError := url.QueryUnescape(encodedSecret)
	if idError != nil || secretError != nil {
		return "", ""
	}
	return clientID, clientSecret
}

func matches(presented, expected string) bool {
	return expected != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

func challengeOf(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func redirectWith(writer http.ResponseWriter, request *http.Request, target string, values url.Values) {
	parsed, err := url.Parse(target)
	if err != nil {
		http.Error(writer, "bad redirect URI", http.StatusBadRequest)
		return
	}
	query := parsed.Query()
	for key, list := range values {
		query[key] = list
	}
	parsed.RawQuery = query.Encode()
	http.Redirect(writer, request, parsed.String(), http.StatusFound) //nolint:gosec // G710: only to registered URIs, or to any when the test registered none
}

func oauthError(writer http.ResponseWriter, status int, code oauthErrorCode) {
	writeJSON(writer, status, map[string]oauthErrorCode{"error": code})
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body) // the client hung up: nothing left to do
}
