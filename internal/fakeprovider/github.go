package fakeprovider

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	defaultGitHubClientID     = "github-client-id"
	defaultGitHubClientSecret = "github-client-secret" //nolint:gosec // G101: the fake's fixed test credential
	githubDefaultPageSize     = 30
	githubMaximumPageSize     = 100
)

// GitHubEndpoint names an endpoint of the fake GitHub for FailWith and Calls.
type GitHubEndpoint string

// The endpoints of the fake GitHub.
const (
	GitHubEndpointAuthorize GitHubEndpoint = "authorize" // GET /login/oauth/authorize
	GitHubEndpointToken     GitHubEndpoint = "token"     // POST /login/oauth/access_token
	GitHubEndpointUser      GitHubEndpoint = "user"      // GET /user
	GitHubEndpointTeams     GitHubEndpoint = "teams"     // GET /user/teams
	GitHubEndpointRevoke    GitHubEndpoint = "revoke"    // DELETE /applications/{client_id}/token
)

// GitHubUser is the user the fake GitHub authenticates (GET /user).
type GitHubUser struct {
	ID        int64
	Login     string
	Name      string
	Email     string
	AvatarURL string
}

// GitHubTeam is one team of the user as GET /user/teams returns it: organization login and team slug,
// in the case GitHub reports them.
type GitHubTeam struct {
	Organization string
	Slug         string
}

// GitHubOptions configure StartGitHub. The zero value is usable.
type GitHubOptions struct {
	ClientID     string       // default "github-client-id"
	ClientSecret string       // default "github-client-secret"
	User         GitHubUser   // default {ID: 1, Login: "octocat", Name: "The Octocat", Email: "octocat@example.com"}
	Teams        []GitHubTeam // the user's teams; SetTeams replaces them
}

// GitHubServer is a fake GitHub on http://127.0.0.1:<port>: the OAuth endpoints (authorize
// auto-approves, the token endpoint checks the client credentials and PKCE S256) and the REST API parts
// the github provider uses. It is safe for concurrent use.
type GitHubServer struct {
	server   *httptest.Server
	options  GitHubOptions
	mutex    sync.Mutex
	teams    []GitHubTeam
	codes    map[string]string // authorization code -> PKCE code challenge, single use
	tokens   map[string]bool   // issued access token -> not revoked
	revoked  []string
	failures map[GitHubEndpoint]int
	calls    map[GitHubEndpoint]int
}

type githubTeamResponse struct {
	Slug         string `json:"slug"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}

// StartGitHub starts a fake GitHub and closes it when the test ends.
func StartGitHub(tb testing.TB, options GitHubOptions) *GitHubServer {
	tb.Helper()
	fake := &GitHubServer{
		options:  withGitHubDefaults(options),
		teams:    slices.Clone(options.Teams),
		codes:    map[string]string{},
		tokens:   map[string]bool{},
		failures: map[GitHubEndpoint]int{},
		calls:    map[GitHubEndpoint]int{},
	}
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("GET /login/oauth/authorize", fake.authorize)
	serveMux.HandleFunc("POST /login/oauth/access_token", fake.token)
	serveMux.HandleFunc("GET /user", fake.user)
	serveMux.HandleFunc("GET /user/teams", fake.userTeams)
	serveMux.HandleFunc("DELETE /applications/{client_id}/token", fake.revoke)
	fake.server = httptest.NewServer(serveMux)
	tb.Cleanup(fake.server.Close)
	return fake
}

func withGitHubDefaults(options GitHubOptions) GitHubOptions {
	if options.ClientID == "" {
		options.ClientID = defaultGitHubClientID
	}
	if options.ClientSecret == "" {
		options.ClientSecret = defaultGitHubClientSecret
	}
	if options.User == (GitHubUser{}) {
		options.User = GitHubUser{ID: 1, Login: "octocat", Name: "The Octocat", Email: "octocat@example.com"}
	}
	options.Teams = nil
	return options
}

// URL returns the base URL, http://127.0.0.1:<port>.
func (s *GitHubServer) URL() string {
	return s.server.URL
}

// AuthorizeURL returns the github.Options.AuthorizeURL to use: URL() + "/login/oauth/authorize".
func (s *GitHubServer) AuthorizeURL() string {
	return s.server.URL + "/login/oauth/authorize"
}

// TokenURL returns the github.Options.TokenURL to use: URL() + "/login/oauth/access_token".
func (s *GitHubServer) TokenURL() string {
	return s.server.URL + "/login/oauth/access_token"
}

// APIURL returns the github.Options.APIURL to use: URL() (the API sits at the root, as on api.github.com).
func (s *GitHubServer) APIURL() string {
	return s.server.URL
}

// ClientID returns the OAuth app's client ID (GitHubOptions.ClientID or its default).
func (s *GitHubServer) ClientID() string {
	return s.options.ClientID
}

// ClientSecret returns the OAuth app's client secret (GitHubOptions.ClientSecret or its default).
func (s *GitHubServer) ClientSecret() string {
	return s.options.ClientSecret
}

// SetTeams replaces the user's teams, e.g. to remove the user from an allowed team.
func (s *GitHubServer) SetTeams(teams []GitHubTeam) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.teams = slices.Clone(teams)
}

// FailWith makes endpoint answer status with a GitHub-style JSON error until called again with status
// 0. The authorize endpoint instead redirects back with error=access_denied (the user declined).
func (s *GitHubServer) FailWith(endpoint GitHubEndpoint, status int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.failures[endpoint] = status
}

// Calls returns how many requests endpoint received, failed ones included.
func (s *GitHubServer) Calls(endpoint GitHubEndpoint) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.calls[endpoint]
}

// RevokedTokens returns the access tokens revoked through DELETE /applications/{client_id}/token, in order.
func (s *GitHubServer) RevokedTokens() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return slices.Clone(s.revoked)
}

// begin counts a call to endpoint and returns the failure status set for it (0 for none).
func (s *GitHubServer) begin(endpoint GitHubEndpoint) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.calls[endpoint]++
	return s.failures[endpoint]
}

func (s *GitHubServer) authorize(writer http.ResponseWriter, request *http.Request) {
	failure := s.begin(GitHubEndpointAuthorize)
	query := request.URL.Query()
	redirectURI, err := url.Parse(query.Get("redirect_uri"))
	switch {
	case query.Get("client_id") != s.options.ClientID || err != nil || !redirectURI.IsAbs():
		writeGitHubError(writer, http.StatusBadRequest, "invalid client_id or redirect_uri")
		return
	case query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "":
		writeGitHubError(writer, http.StatusBadRequest, "PKCE S256 required")
		return
	}
	callback := url.Values{"state": {query.Get("state")}}
	if failure != 0 {
		callback.Set("error", "access_denied")
	} else {
		callback.Set("code", s.issueCode(query.Get("code_challenge")))
	}
	redirectURI.RawQuery = callback.Encode()
	http.Redirect(writer, request, redirectURI.String(), http.StatusFound) //nolint:gosec // G710: an authorize endpoint redirects to the client's redirect_uri by design
}

func (s *GitHubServer) issueCode(challenge string) string {
	code := rand.Text()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.codes[code] = challenge
	return code
}

// token answers like GitHub: problems with the code or the client are HTTP 200 with an "error" field.
func (s *GitHubServer) token(writer http.ResponseWriter, request *http.Request) {
	if failure := s.begin(GitHubEndpointToken); failure != 0 {
		writeGitHubError(writer, failure, "configured failure")
		return
	}
	if err := request.ParseForm(); err != nil {
		writeGitHubError(writer, http.StatusBadRequest, "unreadable form")
		return
	}
	if !s.validClient(request) {
		writeGitHubJSON(writer, http.StatusOK, map[string]string{"error": "incorrect_client_credentials"})
		return
	}
	challenge, found := s.popCode(request.PostForm.Get("code"))
	if !found || !matchesChallenge(request.PostForm.Get("code_verifier"), challenge) {
		writeGitHubJSON(writer, http.StatusOK, map[string]string{"error": "bad_verification_code"})
		return
	}
	writeGitHubJSON(writer, http.StatusOK, map[string]string{"access_token": s.issueToken(), "token_type": "bearer", "scope": "read:org"})
}

func (s *GitHubServer) validClient(request *http.Request) bool {
	clientID, clientSecret, found := request.BasicAuth()
	if !found {
		clientID, clientSecret = request.PostForm.Get("client_id"), request.PostForm.Get("client_secret")
	}
	return clientID == s.options.ClientID && subtle.ConstantTimeCompare([]byte(clientSecret), []byte(s.options.ClientSecret)) == 1
}

func (s *GitHubServer) popCode(code string) (string, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	challenge, found := s.codes[code]
	delete(s.codes, code)
	return challenge, found
}

func matchesChallenge(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return verifier != "" && base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func (s *GitHubServer) issueToken() string {
	token := "gho_" + rand.Text()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.tokens[token] = true
	return token
}

func (s *GitHubServer) user(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeAPI(writer, request, GitHubEndpointUser) {
		return
	}
	user := s.options.User
	writeGitHubJSON(writer, http.StatusOK, map[string]any{
		"id": user.ID, "login": user.Login, "name": user.Name, "email": user.Email, "avatar_url": user.AvatarURL,
	})
}

// userTeams pages like GitHub: per_page (default 30, at most 100) and page (from 1), no Link header needed.
func (s *GitHubServer) userTeams(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeAPI(writer, request, GitHubEndpointTeams) {
		return
	}
	pageSize := githubQueryNumber(request, "per_page", githubDefaultPageSize)
	pageSize = min(pageSize, githubMaximumPageSize)
	page := githubQueryNumber(request, "page", 1)
	s.mutex.Lock()
	teams := s.teams
	s.mutex.Unlock()
	start := len(teams)
	if page <= len(teams) { // also keeps (page-1)*pageSize from overflowing
		start = min((page-1)*pageSize, len(teams))
	}
	end := min(start+pageSize, len(teams))
	body := make([]githubTeamResponse, 0, end-start)
	for _, team := range teams[start:end] {
		response := githubTeamResponse{Slug: team.Slug}
		response.Organization.Login = team.Organization
		body = append(body, response)
	}
	writeGitHubJSON(writer, http.StatusOK, body)
}

func githubQueryNumber(request *http.Request, name string, fallback int) int {
	number, err := strconv.Atoi(request.URL.Query().Get(name))
	if err != nil || number < 1 {
		return fallback
	}
	return number
}

// authorizeAPI counts the call and checks the configured failure and the bearer token; false means it answered.
func (s *GitHubServer) authorizeAPI(writer http.ResponseWriter, request *http.Request, endpoint GitHubEndpoint) bool {
	if failure := s.begin(endpoint); failure != 0 {
		writeGitHubError(writer, failure, "configured failure")
		return false
	}
	authorization := request.Header.Get("Authorization")
	token, found := strings.CutPrefix(authorization, "Bearer ")
	if !found {
		token, found = strings.CutPrefix(authorization, "token ")
	}
	s.mutex.Lock()
	valid := found && s.tokens[token]
	s.mutex.Unlock()
	if !valid {
		writeGitHubError(writer, http.StatusUnauthorized, "Bad credentials")
	}
	return valid
}

func (s *GitHubServer) revoke(writer http.ResponseWriter, request *http.Request) {
	if failure := s.begin(GitHubEndpointRevoke); failure != 0 {
		writeGitHubError(writer, failure, "configured failure")
		return
	}
	clientID, clientSecret, found := request.BasicAuth()
	if !found || clientID != s.options.ClientID || request.PathValue("client_id") != clientID || clientSecret != s.options.ClientSecret {
		writeGitHubError(writer, http.StatusUnauthorized, "Bad credentials")
		return
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil || !s.revokeToken(body.AccessToken) {
		writeGitHubError(writer, http.StatusNotFound, "Not Found")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *GitHubServer) revokeToken(token string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !s.tokens[token] {
		return false
	}
	s.tokens[token] = false
	s.revoked = append(s.revoked, token)
	return true
}

func writeGitHubError(writer http.ResponseWriter, status int, message string) {
	writeGitHubJSON(writer, status, map[string]string{"message": message})
}

func writeGitHubJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	// A write error means the client is gone; a test fake has nobody to tell.
	_ = json.NewEncoder(writer).Encode(body)
}
