package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/oauth2"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/tokenendpoint"
	"github.com/govengers/auth/session"
)

const (
	apiVersion           = "2022-11-28"
	apiMediaType         = "application/vnd.github+json"
	teamsPageSize        = 100
	maximumTeamPages     = 50
	maximumResponseBytes = 10 << 20
)

// user is the part of GET /user the provider reads.
type user struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// team is the part of one GET /user/teams entry the provider reads.
type team struct {
	Slug         string `json:"slug"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}

// revocation is the body of DELETE /applications/{client_id}/token.
type revocation struct {
	AccessToken string `json:"access_token"`
}

// HTTPClient returns a client that sends the session's GitHub token to the GitHub API (APIURL's scheme
// and host) and to nothing else: a redirect to another host, e.g. an archive download, goes without it.
// The token source is static: an expired or revoked token makes GitHub answer 401 and the next refresh
// ends the session. A session without a GitHub token (another provider's, or none): ErrUnauthenticated.
// The client uses Options.HTTPClient's transport and timeout.
func (p *Provider) HTTPClient(ctx context.Context, current session.Session) (*http.Client, error) {
	token, err := sessionToken(ctx, current)
	if err != nil {
		return nil, err
	}
	return p.apiClient(token), nil
}

func (p *Provider) apiClient(token *oauth2.Token) *http.Client {
	client := *p.options.HTTPClient
	client.Transport = &apiTransport{base: client.Transport, api: p.api, token: token}
	return &client
}

// apiTransport sets the token on requests to the GitHub API's scheme and host only.
type apiTransport struct {
	base  http.RoundTripper // nil means http.DefaultTransport
	api   *url.URL
	token *oauth2.Token
}

// RoundTrip implements http.RoundTripper.
func (a *apiTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := a.base
	if base == nil {
		base = http.DefaultTransport
	}
	if request.URL.Scheme != a.api.Scheme || !strings.EqualFold(request.URL.Host, a.api.Host) {
		return base.RoundTrip(request)
	}
	authorized := request.Clone(request.Context())
	a.token.SetAuthHeader(authorized)
	return base.RoundTrip(authorized)
}

// exchange trades the authorization code for a token, proving the PKCE verifier. GitHub refusing the
// code (an error answer below 500) is a refusal (login_failed); a GitHub outage is a plain error.
func (p *Provider) exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	token, err := p.oauth.Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.options.HTTPClient), code, oauth2.VerifierOption(verifier))
	switch {
	case tokenendpoint.Refused(err):
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Code: "login_failed", Reason: "token exchange", Err: tokenendpoint.Error("github: exchange code", err)}
	case err != nil:
		return nil, tokenendpoint.Error("github: exchange code", err)
	}
	return token, nil
}

// fetchUser reads the authenticated user.
func (p *Provider) fetchUser(ctx context.Context, client *http.Client) (user, error) {
	var account user
	if err := p.getJSON(ctx, client, "/user", nil, &account); err != nil {
		return user{}, err
	}
	if account.ID <= 0 || account.Login == "" {
		return user{}, errors.New("github: GET /user answered without id or login")
	}
	return account, nil
}

// fetchTeams reads the normalized teams of the authenticated user, page by page until a page is not full.
// ponytail: stops after 50 pages (5000 teams) like the old library; a user with more is judged on the first 5000.
func (p *Provider) fetchTeams(ctx context.Context, client *http.Client) ([]string, error) {
	var names []string
	for page := 1; page <= maximumTeamPages; page++ {
		var teams []team
		query := url.Values{"per_page": {strconv.Itoa(teamsPageSize)}, "page": {strconv.Itoa(page)}}
		if err := p.getJSON(ctx, client, "/user/teams", query, &teams); err != nil {
			return nil, err
		}
		names = append(names, teamNames(teams)...)
		if len(teams) < teamsPageSize {
			break
		}
	}
	return names, nil
}

func teamNames(teams []team) []string {
	names := make([]string, 0, len(teams))
	for _, team := range teams {
		names = append(names, teamName(team.Organization.Login, team.Slug))
	}
	return names
}

// getJSON GETs APIURL + path and decodes at most 10 MiB of JSON into target. 401: ErrUnauthenticated
// (GitHub rejected the token); any other status but 200: plain error.
func (p *Provider) getJSON(ctx context.Context, client *http.Client, path string, query url.Values, target any) error {
	endpoint := p.options.APIURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("github: GET %s: %w", path, err)
	}
	request.Header.Set("Accept", apiMediaType)
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("github: GET %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "GitHub rejected the token"}
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("github: GET %s answered %d", path, response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumResponseBytes)).Decode(target); err != nil {
		return fmt.Errorf("github: decode %s: %w", path, err)
	}
	return nil
}

// revokeToken deletes the OAuth token at GitHub (DELETE {APIURL}/applications/{ClientID}/token with the
// app's credentials). It is not stopped by a disconnecting client; the default timeout bounds it.
func (p *Provider) revokeToken(ctx context.Context, token *oauth2.Token) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)
	defer cancel()
	body, err := json.Marshal(revocation{AccessToken: token.AccessToken}) //nolint:gosec // G117: the revocation endpoint needs the token it revokes
	if err != nil {
		return fmt.Errorf("github: encode token revocation: %w", err)
	}
	endpoint := p.options.APIURL + "/applications/" + url.PathEscape(p.options.ClientID) + "/token"
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("github: revoke token: %w", err)
	}
	request.SetBasicAuth(p.options.ClientID, p.options.ClientSecret)
	request.Header.Set("Accept", apiMediaType)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	response, err := p.options.HTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("github: revoke token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return fmt.Errorf("github: revoke token: GitHub answered %d", response.StatusCode)
	}
	return nil
}
