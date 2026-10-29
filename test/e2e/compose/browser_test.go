//go:build e2e

// Package compose is the docker compose end-to-end suite: Traefik with the forwardAuth middlewares in
// front of whoami, the forwardauth image and a fake OpenID Connect issuer, started by `just test-e2e`.
package compose

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/jwt"
)

const (
	maximumBodyBytes = 1 << 20
	readyTimeout     = 60 * time.Second
)

// The stack listens on loopback ports that `just test-e2e` picks and exports; see compose.yml.
var (
	appURL    = "http://127.0.0.1:" + os.Getenv("E2E_APP_PORT")
	issuerURL = "http://127.0.0.1:" + os.Getenv("E2E_ISSUER_PORT")
)

func TestMain(m *testing.M) {
	if os.Getenv("E2E_APP_PORT") == "" || os.Getenv("E2E_ISSUER_PORT") == "" {
		fmt.Fprintln(os.Stderr, "E2E_APP_PORT and E2E_ISSUER_PORT are not set: run `just test-e2e`")
		os.Exit(1)
	}
	// `docker compose up --wait` returns when the containers run; poll until the routes answer.
	for _, target := range []string{issuerURL + "/.well-known/openid-configuration", appURL + "/auth/jwks"} {
		if err := waitFor(target); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func waitFor(target string) error {
	deadline := time.Now().Add(readyTimeout)
	client := &http.Client{Timeout: 2 * time.Second}
	lastProblem := "no answer"
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close() // the status is all we need
			if response.StatusCode == http.StatusOK {
				return nil
			}
			lastProblem = response.Status
		} else {
			lastProblem = err.Error()
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("stack not ready: %s did not answer 200 within %s (last: %s)", target, readyTimeout, lastProblem)
}

// browser is an HTTP client with a cookie jar that behaves like a browser, except that it never follows
// a redirect by itself: the test sees every hop and asserts on it.
type browser struct {
	t      *testing.T
	client *http.Client
}

// page is one response, fully read.
type page struct {
	status   int
	location string
	header   http.Header
	body     string
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &browser{t: t, client: &http.Client{
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) get(target string, header http.Header) page {
	b.t.Helper()
	request, err := http.NewRequestWithContext(b.t.Context(), http.MethodGet, target, nil)
	require.NoError(b.t, err)
	for name, values := range header {
		request.Header[name] = values // keep non-canonical names such as X_Forwarded_Host as sent
	}
	response, err := b.client.Do(request)
	require.NoError(b.t, err)
	defer func() { _ = response.Body.Close() }() // read-only response
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumBodyBytes))
	require.NoError(b.t, err)
	return page{status: response.StatusCode, location: response.Header.Get("Location"), header: response.Header, body: string(body)}
}

// signIn walks the whole login for target and returns the browser holding the session. The four hops
// are redirects: target to the login, the login to the issuer, the issuer to the callback and the
// callback back to target.
func signIn(t *testing.T, target string) *browser {
	t.Helper()
	person := newBrowser(t)
	location := appURL + target
	for range 4 {
		hop := person.get(location, nil)
		require.Equal(t, http.StatusFound, hop.status, hop.body)
		location = hop.location
	}
	require.Equal(t, appURL+target, location)
	return person
}

func queryOf(t *testing.T, location string) url.Values {
	t.Helper()
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	return parsed.Query()
}

// bearerIdentity reads the "Authorization: Bearer <jwt>" line whoami echoes and verifies the token
// against the JWKS forwardauth publishes, as a backend would.
func bearerIdentity(t *testing.T, whoamiBody string) *auth.Identity {
	t.Helper()
	var token string
	for line := range strings.SplitSeq(whoamiBody, "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "Authorization: Bearer "); found {
			require.Empty(t, token, "exactly one Authorization header reaches the app")
			token = value
		}
	}
	require.NotEmpty(t, token, whoamiBody)
	verifier, err := jwt.NewVerifier(t.Context(), &jwt.VerifierOptions{JWKSURL: appURL + "/auth/jwks", Issuer: appURL})
	require.NoError(t, err)
	identity, err := verifier.Verify(t.Context(), token)
	require.NoError(t, err)
	return identity
}
