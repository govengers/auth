package jwt

import (
	"context"
	"encoding/base64"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

// keySetServer serves a swappable JWKS handler and counts the fetches.
type keySetServer struct {
	server  *httptest.Server
	fetches atomic.Int32
	mutex   sync.Mutex
	handler http.Handler
}

func newKeySetServer(t *testing.T, handler http.Handler) *keySetServer {
	t.Helper()
	keySets := &keySetServer{handler: handler}
	keySets.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		keySets.fetches.Add(1)
		keySets.mutex.Lock()
		current := keySets.handler
		keySets.mutex.Unlock()
		current.ServeHTTP(writer, request)
	}))
	t.Cleanup(keySets.server.Close)
	return keySets
}

func (k *keySetServer) serve(handler http.Handler) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	k.handler = handler
}

var failingHandler = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusInternalServerError)
})

type testClock struct {
	mutex   sync.Mutex
	instant time.Time
}

func (c *testClock) now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.instant
}

func (c *testClock) advance(duration time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.instant = c.instant.Add(duration)
}

func testVerifierOptions(jwksURL string) *VerifierOptions {
	return &VerifierOptions{JWKSURL: jwksURL, Issuer: testIssuer, Audience: "backend"}
}

// newTestVerifier builds a verifier whose clock, including the time of its first fetch, is clock.
func newTestVerifier(t *testing.T, options *VerifierOptions, clock *testClock) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(t.Context(), options)
	require.NoError(t, err)
	verifier.now = clock.now
	verifier.fetchedAt, verifier.attemptedAt = clock.now(), clock.now()
	return verifier
}

// signWith signs claims with the signer's key and key ID under algorithm.
func signWith(t *testing.T, signer *Signer, algorithm jwa.SignatureAlgorithm, claims map[string]any) string {
	t.Helper()
	token := jwxjwt.New()
	for name, value := range claims {
		require.NoError(t, token.Set(name, value))
	}
	signed, err := jwxjwt.Sign(token, jwxjwt.WithKey(algorithm, signer.signingKey))
	require.NoError(t, err)
	return string(signed)
}

func validClaims(instant time.Time) map[string]any {
	return map[string]any{"iss": testIssuer, "aud": []string{"backend"}, "sub": "42", "iat": instant.Unix(), "exp": instant.Add(time.Minute).Unix()}
}

func requireInvalidToken(t *testing.T, err error) {
	t.Helper()
	var refusal *auth.Error
	require.ErrorAs(t, err, &refusal)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.Equal(t, "invalid_token", refusal.Code)
	require.NoError(t, refusal.Err)
}

func TestNewVerifierRejectsInvalidOptions(t *testing.T) {
	testCases := []struct {
		name      string
		options   *VerifierOptions
		wantError string
	}{
		{name: "nil options", options: nil, wantError: "options are required"},
		{name: "missing URL", options: &VerifierOptions{Issuer: testIssuer}, wantError: "absolute http or https URL"},
		{name: "relative URL", options: &VerifierOptions{JWKSURL: "/auth/jwks", Issuer: testIssuer}, wantError: "absolute http or https URL"},
		{name: "other scheme", options: &VerifierOptions{JWKSURL: "ftp://auth.example.com/jwks", Issuer: testIssuer}, wantError: "absolute http or https URL"},
		{name: "unparsable URL", options: &VerifierOptions{JWKSURL: "http://auth example.com/%zz", Issuer: testIssuer}, wantError: "JWKSURL"},
		{name: "missing issuer", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks"}, wantError: "Issuer is required"},
		{name: "refresh interval in nanoseconds", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks", Issuer: testIssuer, RefreshInterval: 300}, wantError: "RefreshInterval 300ns is below 1m0s"},
		{name: "negative refresh interval", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks", Issuer: testIssuer, RefreshInterval: -time.Hour}, wantError: "is below 1m0s"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			verifier, err := NewVerifier(t.Context(), testCase.options)
			require.ErrorContains(t, err, testCase.wantError)
			require.Nil(t, verifier)
		})
	}
}

func TestNewVerifierAppliesDefaultsToACopy(t *testing.T) {
	signer := newTestSigner(t, fixedClock(signedAt))
	keySets := newKeySetServer(t, signer.JWKSHandler())
	options := &VerifierOptions{JWKSURL: keySets.server.URL, Issuer: testIssuer}

	verifier, err := NewVerifier(t.Context(), options)
	require.NoError(t, err)

	require.Equal(t, &VerifierOptions{JWKSURL: keySets.server.URL, Issuer: testIssuer}, options)
	require.Equal(t, time.Hour, verifier.options.RefreshInterval)
	require.Equal(t, 10*time.Second, verifier.options.HTTPClient.Timeout)
	require.Equal(t, "Authorization", verifier.options.HeaderName)
	require.Equal(t, int32(1), keySets.fetches.Load())
}

func TestNewVerifierFailsWhenTheJWKSCannotBeFetched(t *testing.T) {
	closed := httptest.NewServer(failingHandler)
	closed.Close()
	testCases := []struct {
		name      string
		jwksURL   string
		wantError string
	}{
		{name: "unreachable", jwksURL: closed.URL, wantError: "fetch JWKS"},
		{name: "server error", jwksURL: newKeySetServer(t, failingHandler).server.URL, wantError: "status 500"},
		{name: "not a key set", jwksURL: newKeySetServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(`{"keys":`)) // the client reads what arrives; a lost write fails the parse as well
		})).server.URL, wantError: "parse JWKS"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			verifier, err := NewVerifier(t.Context(), testVerifierOptions(testCase.jwksURL))
			require.ErrorContains(t, err, testCase.wantError)
			require.NotErrorIs(t, err, auth.ErrUnauthenticated)
			require.Nil(t, verifier)
		})
	}
}

func TestVerifyReturnsEveryIdentityField(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	verifier := newTestVerifier(t, testVerifierOptions(newKeySetServer(t, signer.JWKSHandler()).server.URL), clock)
	userID := uuid.MustParse("6f1c2a52-6c43-4c5e-9d3a-0f3d1c2b4a5e")
	identity := &auth.Identity{
		Provider:        "keycloak",
		Subject:         "subject-1",
		UserID:          userID,
		Username:        "ada",
		Name:            "Ada Lovelace",
		Email:           "ada@example.com",
		Picture:         "https://example.com/ada.png",
		Roles:           []string{auth.RoleAdmin},
		OIDCRoles:       []string{"realm-role"},
		OIDCClientRoles: []string{"client-role"},
		Groups:          []string{"/engineering"},
		Teams:           []string{"org/team"},
		Attributes:      map[string][]string{"department": {"r&d"}},
		Claims:          map[string]any{"locale": "de", "nonce": "n-1", "sid": "s-1"},
		Data:            map[string]any{"app": "value"},
		Impersonator:    &auth.Identity{Provider: "password", Subject: "admin-1"},
	}
	token, err := signer.Sign(identity)
	require.NoError(t, err)

	verified, err := verifier.Verify(t.Context(), token)
	require.NoError(t, err)

	tokenID, ok := verified.Claims["jti"].(string)
	require.True(t, ok)
	require.Equal(t, &auth.Identity{
		Provider:        "keycloak",
		Subject:         "subject-1",
		UserID:          userID,
		Username:        "ada",
		Name:            "Ada Lovelace",
		Email:           "ada@example.com",
		Picture:         "https://example.com/ada.png",
		Active:          true,
		Roles:           []string{auth.RoleAdmin},
		OIDCRoles:       []string{"realm-role"},
		OIDCClientRoles: []string{"client-role"},
		Groups:          []string{"/engineering"},
		Teams:           []string{"org/team"},
		Claims: map[string]any{
			"iss": testIssuer, "aud": []any{"backend"}, "jti": tokenID,
			"iat": float64(signedAt.Unix()), "nbf": float64(signedAt.Add(-30 * time.Second).Unix()), "exp": float64(signedAt.Add(5 * time.Minute).Unix()),
			"sub": "subject-1", "provider": "keycloak", "user_id": userID.String(), "preferred_username": "ada", "name": "Ada Lovelace",
			"email": "ada@example.com", "picture": "https://example.com/ada.png", "roles": []any{auth.RoleAdmin}, "realm_roles": []any{"realm-role"},
			"client_roles": []any{"client-role"}, "groups": []any{"/engineering"}, "teams": []any{"org/team"}, "locale": "de",
		},
	}, verified)
}

func TestVerifyRejectsInvalidTokens(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	valid, err := signer.Sign(&auth.Identity{Subject: "42"})
	require.NoError(t, err)
	otherSigner := newTestSigner(t, clock.now)
	forged, err := otherSigner.Sign(&auth.Identity{Subject: "42"})
	require.NoError(t, err)
	keyID, _ := signer.signingKey.KeyID()
	withoutKeyID, err := jwxjwt.Sign(jwxjwt.New(), jwxjwt.WithKey(jwa.RS512(), generateKey(t, 2048)))
	require.NoError(t, err)
	parts := strings.Split(valid, ".")
	testCases := []struct {
		name  string
		token string
	}{
		{name: "garbage", token: "not-a-token"},
		{name: "JSON serialization", token: `{"payload":"e30","signatures":[]}`},
		{name: "no key ID", token: string(withoutKeyID)},
		{name: "wrong issuer", token: signWith(t, signer, jwa.RS512(), withClaim(validClaims(signedAt), "iss", "https://evil.example.com"))},
		{name: "wrong audience", token: signWith(t, signer, jwa.RS512(), withClaim(validClaims(signedAt), "aud", []string{"other"}))},
		{name: "no audience", token: signWith(t, signer, jwa.RS512(), withoutClaim(validClaims(signedAt), "aud"))},
		{name: "not yet valid beyond skew", token: signWith(t, signer, jwa.RS512(), withClaim(validClaims(signedAt), "nbf", signedAt.Add(31*time.Second).Unix()))},
		{name: "no expiry", token: signWith(t, signer, jwa.RS512(), withoutClaim(validClaims(signedAt), "exp"))},
		{name: "tampered payload", token: parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","aud":["backend"],"sub":"admin","exp":9999999999}`)) + "." + parts[2]},
		{name: "signature of another key", token: parts[0] + "." + parts[1] + "." + strings.Split(forged, ".")[2]},
		{name: "algorithm differs from the key's", token: signWith(t, signer, jwa.RS256(), validClaims(signedAt))},
		{name: "unsigned", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"`+keyID+`"}`)) + "." + parts[1] + "."},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			identity, err := verifier.Verify(t.Context(), testCase.token)
			requireInvalidToken(t, err)
			require.Nil(t, identity)
		})
	}
}

func withClaim(claims map[string]any, name string, value any) map[string]any {
	changed := maps.Clone(claims)
	changed[name] = value
	return changed
}

func withoutClaim(claims map[string]any, name string) map[string]any {
	changed := maps.Clone(claims)
	delete(changed, name)
	return changed
}

func TestVerifyChecksTimesWithThirtySecondsSkew(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, fixedClock(signedAt))
	verifier := newTestVerifier(t, testVerifierOptions(newKeySetServer(t, signer.JWKSHandler()).server.URL), clock)
	token, err := signer.Sign(&auth.Identity{Subject: "42"})
	require.NoError(t, err)
	testCases := []struct {
		name      string
		offset    time.Duration // verifier clock relative to signing
		wantValid bool
	}{
		{name: "expired beyond skew", offset: 5*time.Minute + 31*time.Second},
		{name: "expired within skew", offset: 5*time.Minute + 29*time.Second, wantValid: true},
		{name: "issued in the future beyond skew", offset: -31 * time.Second},
		{name: "issued in the future within skew", offset: -29 * time.Second, wantValid: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			verifier.now = fixedClock(signedAt.Add(testCase.offset))

			identity, err := verifier.Verify(t.Context(), token)

			if testCase.wantValid {
				require.NoError(t, err)
				require.Equal(t, "42", identity.Subject)
				return
			}
			requireInvalidToken(t, err)
		})
	}
}

func TestVerifyRefetchesForAnUnknownKeyIDAtMostOncePerMinute(t *testing.T) {
	clock := &testClock{instant: signedAt}
	first, second, third := newTestSigner(t, clock.now), newTestSigner(t, clock.now), newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, first.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	keySets.serve(second.JWKSHandler())
	clock.advance(time.Minute)
	sign := func(signer *Signer) string {
		token, err := signer.Sign(&auth.Identity{Subject: "42"})
		require.NoError(t, err)
		return token
	}

	_, err := verifier.Verify(t.Context(), sign(second))
	require.NoError(t, err, "rotated key is fetched")
	require.Equal(t, int32(2), keySets.fetches.Load())

	_, err = verifier.Verify(t.Context(), sign(third))
	requireInvalidToken(t, err)
	require.Equal(t, int32(2), keySets.fetches.Load(), "no refetch within a minute")

	clock.advance(time.Minute)
	_, err = verifier.Verify(t.Context(), sign(third))
	requireInvalidToken(t, err)
	require.Equal(t, int32(3), keySets.fetches.Load(), "refetch after a minute, key still unknown")

	keySets.serve(third.JWKSHandler())
	clock.advance(59 * time.Second)
	_, err = verifier.Verify(t.Context(), sign(third))
	requireInvalidToken(t, err)
	require.Equal(t, int32(3), keySets.fetches.Load())

	clock.advance(time.Second)
	_, err = verifier.Verify(t.Context(), sign(third))
	require.NoError(t, err)
	require.Equal(t, int32(4), keySets.fetches.Load())

	_, err = verifier.Verify(t.Context(), sign(first))
	requireInvalidToken(t, err)
}

func TestVerifyRefreshesKeysAfterTheRefreshInterval(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	options := testVerifierOptions(keySets.server.URL)
	options.RefreshInterval = 2 * time.Hour
	verifier := newTestVerifier(t, options, clock)

	for _, step := range []struct {
		advance     time.Duration
		wantFetches int32
	}{
		{advance: 0, wantFetches: 1},
		{advance: 2*time.Hour - time.Second, wantFetches: 1},
		{advance: time.Second, wantFetches: 2},
		{advance: time.Hour, wantFetches: 2},
	} {
		clock.advance(step.advance)
		token, err := signer.Sign(&auth.Identity{Subject: "42"})
		require.NoError(t, err)

		_, err = verifier.Verify(t.Context(), token)

		require.NoError(t, err)
		require.Equal(t, step.wantFetches, keySets.fetches.Load())
	}
}

func TestVerifyKeepsTheKeysWhenARefreshFails(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	keySets.serve(failingHandler)
	clock.advance(time.Hour)
	token, err := signer.Sign(&auth.Identity{Subject: "42"})
	require.NoError(t, err)

	identity, refreshError, err := verifier.verify(t.Context(), token)
	require.NoError(t, err)
	require.Equal(t, "42", identity.Subject)
	require.ErrorContains(t, refreshError, "status 500")

	_, refreshError, err = verifier.verify(t.Context(), token)
	require.NoError(t, err)
	require.NoError(t, refreshError, "no new attempt within a minute")
	require.Equal(t, int32(2), keySets.fetches.Load())

	clock.advance(time.Minute)
	keySets.serve(signer.JWKSHandler())
	_, refreshError, err = verifier.verify(t.Context(), token)
	require.NoError(t, err)
	require.NoError(t, refreshError)
	require.Equal(t, int32(3), keySets.fetches.Load())
}

func TestVerifyFailsWhenTheRefetchForAnUnknownKeyIDFails(t *testing.T) {
	clock := &testClock{instant: signedAt}
	keySets := newKeySetServer(t, newTestSigner(t, clock.now).JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	keySets.serve(failingHandler)
	clock.advance(time.Minute)
	token, err := newTestSigner(t, clock.now).Sign(&auth.Identity{Subject: "42"})
	require.NoError(t, err)

	identity, err := verifier.Verify(t.Context(), token)

	require.ErrorContains(t, err, "status 500")
	require.NotErrorIs(t, err, auth.ErrUnauthenticated)
	require.Nil(t, identity)
}

func TestVerifyIsSafeForConcurrentUse(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	clock.advance(time.Hour)
	token, err := signer.Sign(&auth.Identity{Subject: "42"})
	require.NoError(t, err)

	var waitGroup sync.WaitGroup
	verifyErrors := make(chan error, 8)
	for range 8 {
		waitGroup.Go(func() {
			_, verifyError := verifier.Verify(t.Context(), token)
			verifyErrors <- verifyError
		})
	}
	waitGroup.Wait()
	close(verifyErrors)

	for verifyError := range verifyErrors {
		require.NoError(t, verifyError)
	}
	require.Equal(t, int32(2), keySets.fetches.Load(), "one refresh for all")
}

func TestMiddleware(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	token, err := signer.Sign(&auth.Identity{Provider: "github", Subject: "42"})
	require.NoError(t, err)
	testCases := []struct {
		name       string
		headerName string
		header     http.Header
		wantStatus int
		wantBody   string
		wantResult auth.Result
	}{
		{name: "no header", header: http.Header{}, wantStatus: http.StatusUnauthorized, wantBody: `{"code":"unauthenticated","message":"authentication required"}`, wantResult: auth.ResultDenied},
		{name: "other scheme", header: http.Header{"Authorization": {"Basic " + token}}, wantStatus: http.StatusUnauthorized, wantBody: `{"code":"unauthenticated","message":"authentication required"}`, wantResult: auth.ResultDenied},
		{name: "empty bearer", header: http.Header{"Authorization": {"Bearer "}}, wantStatus: http.StatusUnauthorized, wantBody: `{"code":"unauthenticated","message":"authentication required"}`, wantResult: auth.ResultDenied},
		{name: "invalid token", header: http.Header{"Authorization": {"Bearer " + token + "x"}}, wantStatus: http.StatusUnauthorized, wantBody: `{"code":"invalid_token","message":"authentication required"}`, wantResult: auth.ResultDenied},
		{name: "valid token", header: http.Header{"Authorization": {"bearer " + token}}, wantStatus: http.StatusOK, wantBody: "42", wantResult: auth.ResultSuccess},
		{name: "valid token in another header", headerName: "X-Auth-Token", header: http.Header{"X-Auth-Token": {"Bearer " + token}}, wantStatus: http.StatusOK, wantBody: "42", wantResult: auth.ResultSuccess},
		{name: "token in the default header while another is configured", headerName: "X-Auth-Token", header: http.Header{"Authorization": {"Bearer " + token}}, wantStatus: http.StatusUnauthorized, wantBody: `{"code":"unauthenticated","message":"authentication required"}`, wantResult: auth.ResultDenied},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var outcomes []auth.Outcome
			options := testVerifierOptions(newKeySetServer(t, signer.JWKSHandler()).server.URL)
			options.HeaderName = testCase.headerName
			options.Observer = func(_ context.Context, outcome auth.Outcome) { outcomes = append(outcomes, outcome) }
			verifier := newTestVerifier(t, options, clock)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/items", nil)
			request.Header = testCase.header
			recorder := httptest.NewRecorder()

			verifier.Middleware()(subjectHandler()).ServeHTTP(recorder, request)

			require.Equal(t, testCase.wantStatus, recorder.Code)
			require.Equal(t, testCase.wantBody, strings.TrimSpace(recorder.Body.String()))
			require.Len(t, outcomes, 1)
			require.Equal(t, providerName, outcomes[0].Provider)
			require.Equal(t, auth.ActionAuthenticate, outcomes[0].Action)
			require.Equal(t, testCase.wantResult, outcomes[0].Result)
			if testCase.wantResult == auth.ResultSuccess {
				require.NoError(t, outcomes[0].Err)
				require.Equal(t, "42", outcomes[0].Identity.Subject)
				return
			}
			require.ErrorIs(t, outcomes[0].Err, auth.ErrUnauthenticated)
			require.Nil(t, outcomes[0].Identity)
		})
	}
}

// subjectHandler answers with the subject of the identity in the request context.
func subjectHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(auth.IdentityFrom(request.Context()).Subject)) // the recorder never fails a write
	})
}

func TestMiddlewareAnswersAFailedKeyFetchWithInternalError(t *testing.T) {
	clock := &testClock{instant: signedAt}
	var outcomes []auth.Outcome
	keySets := newKeySetServer(t, newTestSigner(t, clock.now).JWKSHandler())
	options := testVerifierOptions(keySets.server.URL)
	options.Observer = func(_ context.Context, outcome auth.Outcome) { outcomes = append(outcomes, outcome) }
	verifier := newTestVerifier(t, options, clock)
	keySets.serve(failingHandler)
	clock.advance(time.Minute)
	token, err := newTestSigner(t, clock.now).Sign(&auth.Identity{Subject: "42"})
	require.NoError(t, err)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/items", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	verifier.Middleware()(subjectHandler()).ServeHTTP(recorder, request)

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.JSONEq(t, `{"code":"internal","message":"internal error"}`, recorder.Body.String())
	require.Len(t, outcomes, 1)
	require.Equal(t, auth.ResultError, outcomes[0].Result)
	require.ErrorContains(t, outcomes[0].Err, "status 500")
}

func TestMiddlewareReportsAFailedRefreshAsDegradedSuccess(t *testing.T) {
	clock := &testClock{instant: signedAt}
	var outcomes []auth.Outcome
	signer := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	options := testVerifierOptions(keySets.server.URL)
	options.Observer = func(_ context.Context, outcome auth.Outcome) { outcomes = append(outcomes, outcome) }
	verifier := newTestVerifier(t, options, clock)
	keySets.serve(failingHandler)
	clock.advance(time.Hour)
	token, err := signer.Sign(&auth.Identity{Subject: "42"})
	require.NoError(t, err)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/items", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	verifier.Middleware()(subjectHandler()).ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Len(t, outcomes, 1)
	require.Equal(t, auth.ResultSuccess, outcomes[0].Result)
	require.ErrorContains(t, outcomes[0].Err, "status 500")
}
