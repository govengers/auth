package fakeprovider_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeprovider"
)

func githubCode(t *testing.T, fake *fakeprovider.GitHubServer) string {
	t.Helper()
	digest := sha256.Sum256([]byte(codeVerifier))
	parameters := url.Values{
		"client_id": {fake.ClientID()}, "redirect_uri": {redirectURI}, "state": {"s1"},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])},
	}
	return codeFrom(t, get(t, fake.AuthorizeURL()+"?"+parameters.Encode()))
}

// githubExchange redeems code like the github provider (credentials in the form) and returns the JSON answer.
func githubExchange(t *testing.T, fake *fakeprovider.GitHubServer, code, callbackURI string) map[string]string {
	t.Helper()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callbackURI}, "code_verifier": {codeVerifier},
		"client_id": {fake.ClientID()}, "client_secret": {fake.ClientSecret()},
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fake.TokenURL(), strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := noRedirects().Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }() // read-only response, close error carries no information
	require.Equal(t, http.StatusOK, response.StatusCode, "GitHub answers token errors with 200")
	var body map[string]string
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	return body
}

func TestGitHubTokenEndpointBindsTheCodeToItsRedirectURI(t *testing.T) {
	fake := fakeprovider.StartGitHub(t, fakeprovider.GitHubOptions{})

	code := githubCode(t, fake)
	require.Equal(t, "redirect_uri_mismatch", githubExchange(t, fake, code, "http://other.test/callback")["error"])
	require.Equal(t, "bad_verification_code", githubExchange(t, fake, code, redirectURI)["error"], "the refused code is used up")

	answer := githubExchange(t, fake, githubCode(t, fake), redirectURI)
	require.Empty(t, answer["error"])
	require.True(t, strings.HasPrefix(answer["access_token"], "gho_"))
}
