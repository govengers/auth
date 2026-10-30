package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
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

func requireInvalidToken(t *testing.T, err error, wantReason string) {
	t.Helper()
	var refusal *auth.Error
	require.ErrorAs(t, err, &refusal)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	require.Equal(t, "invalid_token", refusal.Code)
	require.Equal(t, wantReason, refusal.Reason)
	require.NoError(t, refusal.Err)
}

func TestNewVerifierRejectsInvalidOptions(t *testing.T) {
	const wantInsecureURL = "must be an https URL, or http on a loopback host or with InsecureJWKSURL, without user info"
	testCases := []struct {
		name      string
		options   *VerifierOptions
		wantError string
	}{
		{name: "nil options", options: nil, wantError: "options are required"},
		{name: "missing URL", options: &VerifierOptions{Issuer: testIssuer, Audience: "backend"}, wantError: wantInsecureURL},
		{name: "relative URL", options: &VerifierOptions{JWKSURL: "/auth/jwks", Issuer: testIssuer, Audience: "backend"}, wantError: wantInsecureURL},
		{name: "other scheme", options: &VerifierOptions{JWKSURL: "ftp://auth.example.com/jwks", Issuer: testIssuer, Audience: "backend"}, wantError: wantInsecureURL},
		{name: "plain http on another host", options: &VerifierOptions{JWKSURL: "http://forwardauth:8080/auth/jwks", Issuer: testIssuer, Audience: "backend"}, wantError: wantInsecureURL},
		{name: "insecure JWKS URL keeps refusing user info", options: &VerifierOptions{JWKSURL: "http://user:password@forwardauth:8080/auth/jwks", InsecureJWKSURL: true, Issuer: testIssuer, Audience: "backend"}, wantError: wantInsecureURL},
		{name: "insecure JWKS URL keeps refusing other schemes", options: &VerifierOptions{JWKSURL: "ftp://forwardauth/jwks", InsecureJWKSURL: true, Issuer: testIssuer, Audience: "backend"}, wantError: wantInsecureURL},
		{name: "user info", options: &VerifierOptions{JWKSURL: "https://user:password@auth.example.com/jwks", Issuer: testIssuer, Audience: "backend"}, wantError: wantInsecureURL},
		{name: "unparsable URL", options: &VerifierOptions{JWKSURL: "http://auth example.com/%zz", Issuer: testIssuer, Audience: "backend"}, wantError: "JWKSURL is no URL"},
		{name: "missing issuer", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks", Audience: "backend"}, wantError: "Issuer is required"},
		{name: "missing audience", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks", Issuer: testIssuer}, wantError: "Audience is required"},
		{name: "refresh interval in nanoseconds", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks", Issuer: testIssuer, Audience: "backend", RefreshInterval: 300}, wantError: "RefreshInterval 300ns is below 1m0s"},
		{name: "negative refresh interval", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks", Issuer: testIssuer, Audience: "backend", RefreshInterval: -time.Hour}, wantError: "is below 1m0s"},
		{name: "maximum key age below refresh interval", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks", Issuer: testIssuer, Audience: "backend", RefreshInterval: 2 * time.Hour, MaximumKeyAge: time.Hour}, wantError: "MaximumKeyAge 1h0m0s is below RefreshInterval 2h0m0s"},
		{name: "refresh interval above the default maximum key age", options: &VerifierOptions{JWKSURL: "https://auth.example.com/jwks", Issuer: testIssuer, Audience: "backend", RefreshInterval: 25 * time.Hour}, wantError: "MaximumKeyAge 24h0m0s is below RefreshInterval 25h0m0s"},
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
	options := testVerifierOptions(keySets.server.URL)

	verifier, err := NewVerifier(t.Context(), options)
	require.NoError(t, err)

	require.Equal(t, testVerifierOptions(keySets.server.URL), options)
	require.Equal(t, time.Hour, verifier.options.RefreshInterval)
	require.Equal(t, 24*time.Hour, verifier.options.MaximumKeyAge)
	require.Equal(t, 10*time.Second, verifier.options.HTTPClient.Timeout)
	require.Equal(t, "Authorization", verifier.options.HeaderName)
	require.Equal(t, int32(1), keySets.fetches.Load())
}

func TestInsecureJWKSURLAllowsPlainHTTPOnAnyHost(t *testing.T) {
	options := &VerifierOptions{JWKSURL: "http://forwardauth:8080/auth/jwks", InsecureJWKSURL: true, Issuer: testIssuer, Audience: "backend"}

	resolved, err := resolveVerifierOptions(options)

	require.NoError(t, err)
	require.Equal(t, "http://forwardauth:8080/auth/jwks", resolved.JWKSURL)
}

// truncatedKeySet serves a JWKS document that ends early.
var truncatedKeySet = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
	_, _ = writer.Write([]byte(`{"keys":`)) // the client reads what arrives; a lost write fails the parse as well
})

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
		{name: "not a key set", jwksURL: newKeySetServer(t, truncatedKeySet).server.URL, wantError: "parse JWKS"},
		{name: "larger than 1 MiB", jwksURL: newKeySetServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(`{"keys":[],"padding":"` + strings.Repeat("x", 1<<20) + `"}`)) // a lost write fails the test
		})).server.URL, wantError: "is larger than 1 MiB"},
		{name: "redirect", jwksURL: newKeySetServer(t, http.RedirectHandler(newKeySetServer(t, truncatedKeySet).server.URL, http.StatusFound)).server.URL, wantError: "redirect refused"},
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

// keySetHandler serves {"keys": keys}.
func keySetHandler(t *testing.T, keys ...map[string]any) http.Handler {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(body) // the client reads what arrives; a lost write fails the parse
	})
}

// publishedKey returns the signer's JWKS entry as JSON members.
func publishedKey(t *testing.T, signer *Signer) map[string]any {
	t.Helper()
	var keySet struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(signer.keySetJSON, &keySet))
	return keySet.Keys[0]
}

// hmacKey returns a symmetric JWK with key ID "oct-1" and alg HS256, as JSON members and as a signing key.
func hmacKey(t *testing.T) (map[string]any, jwk.Key) {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	key, err := jwk.Import(secret)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "oct-1"))
	return map[string]any{"kty": "oct", "kid": "oct-1", "alg": "HS256", "k": base64.RawURLEncoding.EncodeToString(secret)}, key
}

func TestNewVerifierFailsWithoutAnRSASigningKey(t *testing.T) {
	signerKey := publishedKey(t, newTestSigner(t, fixedClock(signedAt)))
	symmetricKey, _ := hmacKey(t)
	encryptionKey := maps.Clone(signerKey)
	encryptionKey["use"] = "enc"
	keyWithoutAlgorithm := maps.Clone(signerKey)
	delete(keyWithoutAlgorithm, "alg")
	keyWithEncryptionAlgorithm := maps.Clone(signerKey)
	keyWithEncryptionAlgorithm["alg"] = "RSA-OAEP"
	delete(keyWithEncryptionAlgorithm, "use")
	keyWithECAlgorithm := maps.Clone(signerKey)
	keyWithECAlgorithm["alg"] = "ES256"
	keyWithoutKeyID := maps.Clone(signerKey)
	delete(keyWithoutKeyID, "kid")
	testCases := []struct {
		name string
		key  map[string]any
	}{
		{name: "symmetric key", key: symmetricKey},
		{name: "encryption key", key: encryptionKey},
		{name: "key without alg", key: keyWithoutAlgorithm},
		{name: "RSA key with an encryption alg and no use", key: keyWithEncryptionAlgorithm},
		{name: "RSA key with an EC alg", key: keyWithECAlgorithm},
		{name: "key without kid", key: keyWithoutKeyID},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			keySets := newKeySetServer(t, keySetHandler(t, testCase.key))

			verifier, err := NewVerifier(t.Context(), testVerifierOptions(keySets.server.URL))

			require.ErrorContains(t, err, "JWKS has no RSA signing key with alg and kid")
			require.Nil(t, verifier)
		})
	}
}

func TestVerifyIgnoresSymmetricKeysOfTheJWKS(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	symmetricKey, signingKey := hmacKey(t)
	verifier := newTestVerifier(t, testVerifierOptions(newKeySetServer(t, keySetHandler(t, publishedKey(t, signer), symmetricKey)).server.URL), clock)
	token := jwxjwt.New()
	for name, value := range validClaims(signedAt) {
		require.NoError(t, token.Set(name, value))
	}
	forged, err := jwxjwt.Sign(token, jwxjwt.WithKey(jwa.HS256(), signingKey))
	require.NoError(t, err)
	valid, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)

	_, err = verifier.Verify(t.Context(), string(forged))
	requireInvalidToken(t, err, "unknown key ID")

	identity, err := verifier.Verify(t.Context(), valid)
	require.NoError(t, err)
	require.Equal(t, "42", identity.Subject)
}

func TestVerifySkipsUnparsableKeysOfTheJWKS(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	unknownType := map[string]any{"kty": "AKP", "kid": "pq-1", "alg": "ML-DSA-44", "pub": "AAAA"}
	brokenModulus := map[string]any{"kty": "RSA", "kid": "broken-1", "alg": "RS512", "n": "!!!", "e": "AQAB"}
	withoutType := map[string]any{"kid": "no-kty"}
	keySets := newKeySetServer(t, keySetHandler(t, unknownType, brokenModulus, withoutType, publishedKey(t, signer)))
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)

	identity, err := verifier.Verify(t.Context(), token)

	require.NoError(t, err)
	require.Equal(t, "42", identity.Subject)
}

func TestVerifierErrorsOmitCredentialsOfTheJWKSURL(t *testing.T) {
	withCredentials := func(serverURL string) string {
		location, err := url.Parse(serverURL)
		require.NoError(t, err)
		location.RawQuery = "token=secret-query"
		return location.String()
	}
	closed := httptest.NewServer(failingHandler)
	closed.Close()
	testCases := []struct {
		name      string
		jwksURL   string
		wantError string
	}{
		{name: "unparsable", jwksURL: "http://user:secret-password@auth example.com/%zz?token=secret-query", wantError: "JWKSURL is no URL"},
		{name: "other scheme", jwksURL: "ftp://user:secret-password@auth.example.com/jwks?token=secret-query", wantError: "JWKSURL ftp://auth.example.com/jwks must be"},
		{name: "user info", jwksURL: "https://user:secret-password@auth.example.com/jwks?token=secret-query", wantError: "JWKSURL https://auth.example.com/jwks must be"},
		{name: "unreachable", jwksURL: withCredentials(closed.URL), wantError: "fetch JWKS: Get \"" + closed.URL + "\""},
		{name: "server error", jwksURL: withCredentials(newKeySetServer(t, failingHandler).server.URL), wantError: "status 500"},
		{name: "not a key set", jwksURL: withCredentials(newKeySetServer(t, truncatedKeySet).server.URL), wantError: "parse JWKS http://127.0.0.1"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewVerifier(t.Context(), testVerifierOptions(testCase.jwksURL))

			require.ErrorContains(t, err, testCase.wantError)
			require.NotContains(t, err.Error(), "secret")
		})
	}
}

// rawAnswer answers with the bytes of answer instead of an HTTP response written by net/http.
func rawAnswer(answer string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		connection, _, err := http.NewResponseController(writer).Hijack()
		if err != nil {
			return
		}
		_, _ = connection.Write([]byte(answer)) // the client may already have given up
		_ = connection.Close()                  // nothing to flush
	}
}

// A JWKS response's bytes may carry personal data, so they reach neither the errors of NewVerifier and
// Verify nor an outcome, at construction and during a refresh [LOG-009].
func TestVerifierErrorsOmitTheJWKSResponse(t *testing.T) {
	const canary = "alice@example.test"
	testCases := []struct {
		name      string
		handler   http.Handler
		wantError string
	}{
		{name: "keys not an array", handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(`{"keys":"` + canary + `"}`)) // a lost write fails the parse as well
		}), wantError: "parse JWKS http://127.0.0.1"},
		{name: "malformed trailer", handler: rawAnswer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nX-User: " + canary + "\x00\r\n\r\n"), wantError: "read JWKS http://127.0.0.1"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name+" at construction", func(t *testing.T) {
			_, err := NewVerifier(t.Context(), testVerifierOptions(newKeySetServer(t, testCase.handler).server.URL))

			require.ErrorContains(t, err, testCase.wantError)
			require.NotContains(t, err.Error(), canary)
		})
		t.Run(testCase.name+" during a refresh", func(t *testing.T) {
			clock := &testClock{instant: signedAt}
			var outcomes []auth.Outcome
			signer := newTestSigner(t, clock.now)
			keySets := newKeySetServer(t, signer.JWKSHandler())
			options := testVerifierOptions(keySets.server.URL)
			options.Observer = func(_ context.Context, outcome auth.Outcome) { outcomes = append(outcomes, outcome) }
			verifier := newTestVerifier(t, options, clock)
			keySets.serve(testCase.handler)
			clock.advance(time.Hour)
			token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
			require.NoError(t, err)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/items", nil)
			request.Header.Set("Authorization", "Bearer "+token)

			verifier.Middleware()(subjectHandler()).ServeHTTP(httptest.NewRecorder(), request)

			require.Len(t, outcomes, 1)
			require.ErrorContains(t, outcomes[0].Err, testCase.wantError)
			require.NotContains(t, outcomes[0].Err.Error(), canary)
		})
	}
}

func TestVerifyReturnsEveryIdentityField(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	verifier := newTestVerifier(t, testVerifierOptions(newKeySetServer(t, signer.JWKSHandler()).server.URL), clock)
	userID := uuid.MustParse("6f1c2a52-6c43-4c5e-9d3a-0f3d1c2b4a5e")
	adminID := uuid.MustParse("0b6f2c1e-7a3d-4c55-9f0e-2d8b1a6c4e71")
	identity := &auth.Identity{
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
		Permissions:     []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}, {Resource: auth.AllResources, Access: auth.AccessRead}},
		Attributes:      map[string][]string{"department": {"r&d"}},
		Claims:          map[string]any{"locale": "de", "nonce": "n-1", "sid": "s-1"},
		Data:            map[string]any{"app": "value"},
		Impersonator:    &auth.Identity{Provider: "password", Subject: "admin-1", UserID: adminID, Active: true, Roles: []string{auth.RoleAdmin}},
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
		Permissions:     []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}, {Resource: auth.AllResources, Access: auth.AccessRead}},
		Claims: map[string]any{
			"iss": testIssuer, "aud": []any{"backend"}, "jti": tokenID,
			"iat": float64(signedAt.Unix()), "nbf": float64(signedAt.Add(-30 * time.Second).Unix()), "exp": float64(signedAt.Add(5 * time.Minute).Unix()),
			"sub": "subject-1", "provider": "keycloak", "user_id": userID.String(), "preferred_username": "ada", "name": "Ada Lovelace",
			"email": "ada@example.com", "picture": "https://example.com/ada.png", "roles": []any{auth.RoleAdmin}, "realm_roles": []any{"realm-role"},
			"client_roles": []any{"client-role"}, "groups": []any{"/engineering"}, "teams": []any{"org/team"},
			"permissions": []any{"builds:write", "*:read"}, "locale": "de",
			"act": map[string]any{"sub": "admin-1", "provider": "password", "user_id": adminID.String()},
		},
		Impersonator: &auth.Identity{Provider: "password", Subject: "admin-1", UserID: adminID, Active: true},
	}, verified)
}

func TestVerifyDoesNotTakePermissionsFromForgedClaims(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	verifier := newTestVerifier(t, testVerifierOptions(newKeySetServer(t, signer.JWKSHandler()).server.URL), clock)
	token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true, Claims: map[string]any{"permissions": []any{"*:write"}, "roles": []any{auth.RoleAdmin}}})
	require.NoError(t, err)

	identity, err := verifier.Verify(t.Context(), token)

	require.NoError(t, err)
	require.Empty(t, identity.Permissions)
	require.Empty(t, identity.Roles)
	require.NotContains(t, identity.Claims, "permissions")
	require.False(t, identity.Permits("builds", auth.AccessRead))
}

func TestVerifyDropsInvalidPermissionEntries(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	verifier := newTestVerifier(t, testVerifierOptions(newKeySetServer(t, signer.JWKSHandler()).server.URL), clock)
	token := signWith(t, signer, jwa.RS512(), withClaim(validClaims(signedAt), "permissions", []any{"builds:write", 7, "BUILDS:write", "*:admin", "deployments:read"}))

	identity, err := verifier.Verify(t.Context(), token)

	require.NoError(t, err)
	require.Equal(t, []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}, {Resource: "deployments", Access: auth.AccessRead}}, identity.Permissions)
}

func TestVerifyRejectsInvalidTokens(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	valid, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)
	otherSigner := newTestSigner(t, clock.now)
	forged, err := otherSigner.Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)
	keyID, _ := signer.signingKey.KeyID()
	withoutKeyID, err := jwxjwt.Sign(jwxjwt.New(), jwxjwt.WithKey(jwa.RS512(), generateKey(t, 2048)))
	require.NoError(t, err)
	parts := strings.Split(valid, ".")
	testCases := []struct {
		name       string
		token      string
		wantReason string
	}{
		{name: "garbage", token: "not-a-token", wantReason: "malformed token"},
		{name: "JSON serialization", token: `{"payload":"e30","signatures":[]}`, wantReason: "malformed token"},
		{name: "no key ID", token: string(withoutKeyID), wantReason: "token header has no kid"},
		{name: "unknown key ID", token: forged, wantReason: "unknown key ID"},
		{name: "wrong issuer", token: signWith(t, signer, jwa.RS512(), withClaim(validClaims(signedAt), "iss", "https://evil.example.com")), wantReason: "issuer mismatch"},
		{name: "wrong audience", token: signWith(t, signer, jwa.RS512(), withClaim(validClaims(signedAt), "aud", []string{"other"})), wantReason: "audience mismatch"},
		{name: "no audience", token: signWith(t, signer, jwa.RS512(), withoutClaim(validClaims(signedAt), "aud")), wantReason: "audience mismatch"},
		{name: "not yet valid beyond skew", token: signWith(t, signer, jwa.RS512(), withClaim(validClaims(signedAt), "nbf", signedAt.Add(31*time.Second).Unix())), wantReason: "token not yet valid"},
		{name: "no expiry", token: signWith(t, signer, jwa.RS512(), withoutClaim(validClaims(signedAt), "exp")), wantReason: "expiry missing"},
		{name: "expiry of the wrong type", token: signPayload(t, signer, `{"iss":"`+testIssuer+`","aud":["backend"],"exp":"MARKER"}`), wantReason: "token invalid"},
		{name: "tampered payload", token: parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","aud":["backend"],"sub":"admin","exp":9999999999}`)) + "." + parts[2], wantReason: "signature invalid"},
		{name: "signature of another key", token: parts[0] + "." + parts[1] + "." + strings.Split(forged, ".")[2], wantReason: "signature invalid"},
		{name: "algorithm differs from the key's", token: signWith(t, signer, jwa.RS256(), validClaims(signedAt)), wantReason: "signature invalid"},
		{name: "unsigned", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"`+keyID+`"}`)) + "." + parts[1] + ".", wantReason: "signature invalid"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			identity, err := verifier.Verify(t.Context(), testCase.token)
			requireInvalidToken(t, err, testCase.wantReason)
			require.Nil(t, identity)
		})
	}
}

// signPayload signs payload as it is with the signer's key and key ID, so claims may have any type.
func signPayload(t *testing.T, signer *Signer, payload string) string {
	t.Helper()
	keyID, _ := signer.signingKey.KeyID()
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, keyID))
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS512(), signer.signingKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return string(signed)
}

func TestVerifyKeepsTokenMaterialOutOfTheReason(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	verifier := newTestVerifier(t, testVerifierOptions(newKeySetServer(t, signer.JWKSHandler()).server.URL), clock)
	longKeyID := strings.Repeat("K", 10<<10)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS512","kid":"` + longKeyID + `"}`))
	testCases := []struct {
		name   string
		token  string
		marker string
	}{
		{name: "long unknown key ID", token: header + "." + strings.Split(signWith(t, signer, jwa.RS512(), validClaims(signedAt)), ".")[1] + ".c2ln", marker: "KKKK"},
		{name: "claim value", token: signPayload(t, signer, `{"iss":"`+testIssuer+`","aud":["backend"],"exp":"MARKER-EXPIRY"}`), marker: "MARKER"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := verifier.Verify(t.Context(), testCase.token)

			var refusal *auth.Error
			require.ErrorAs(t, err, &refusal)
			require.Less(t, len(err.Error()), 100)
			require.NotContains(t, err.Error(), testCase.marker)
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
	token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)
	testCases := []struct {
		name       string
		offset     time.Duration // verifier clock relative to signing
		wantValid  bool
		wantReason string
	}{
		{name: "expired beyond skew", offset: 5*time.Minute + 31*time.Second, wantReason: "token expired"},
		{name: "expired within skew", offset: 5*time.Minute + 29*time.Second, wantValid: true},
		{name: "issued in the future beyond skew", offset: -31 * time.Second, wantReason: "token issued in the future"},
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
			requireInvalidToken(t, err, testCase.wantReason)
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
		token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
		require.NoError(t, err)
		return token
	}

	_, err := verifier.Verify(t.Context(), sign(second))
	require.NoError(t, err, "rotated key is fetched")
	require.Equal(t, int32(2), keySets.fetches.Load())

	_, err = verifier.Verify(t.Context(), sign(third))
	requireInvalidToken(t, err, "unknown key ID")
	require.Equal(t, int32(2), keySets.fetches.Load(), "no refetch within a minute")

	clock.advance(time.Minute)
	_, err = verifier.Verify(t.Context(), sign(third))
	requireInvalidToken(t, err, "unknown key ID")
	require.Equal(t, int32(3), keySets.fetches.Load(), "refetch after a minute, key still unknown")

	keySets.serve(third.JWKSHandler())
	clock.advance(59 * time.Second)
	_, err = verifier.Verify(t.Context(), sign(third))
	requireInvalidToken(t, err, "unknown key ID")
	require.Equal(t, int32(3), keySets.fetches.Load())

	clock.advance(time.Second)
	_, err = verifier.Verify(t.Context(), sign(third))
	require.NoError(t, err)
	require.Equal(t, int32(4), keySets.fetches.Load())

	_, err = verifier.Verify(t.Context(), sign(first))
	requireInvalidToken(t, err, "unknown key ID")
}

func TestVerifyFetchesARotatedKeyForACancelledRequest(t *testing.T) {
	clock := &testClock{instant: signedAt}
	rotated := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, newTestSigner(t, clock.now).JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	keySets.serve(rotated.JWKSHandler())
	clock.advance(time.Minute)
	token, err := rotated.Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = verifier.Verify(cancelled, token)
	require.NoError(t, err, "the client's disconnect does not end the shared fetch")

	_, err = verifier.Verify(t.Context(), token)
	require.NoError(t, err)
	require.Equal(t, int32(2), keySets.fetches.Load())
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
		token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
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
	token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
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

// A key the signer rotated out must not stay trusted forever while its JWKS is unreachable.
func TestVerifyStopsTrustingKeysOlderThanTheMaximumKeyAge(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	keySets.serve(failingHandler)
	verify := func() (*auth.Identity, error, error) {
		token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
		require.NoError(t, err)
		return verifier.verify(t.Context(), token)
	}

	clock.advance(24*time.Hour - time.Minute)
	identity, refreshError, err := verify()
	require.NoError(t, err)
	require.Equal(t, "42", identity.Subject)
	require.ErrorContains(t, refreshError, "status 500")

	clock.advance(time.Minute)
	identity, _, err = verify()
	require.ErrorContains(t, err, "status 500")
	require.NotErrorIs(t, err, auth.ErrUnauthenticated)
	require.Nil(t, identity)

	identity, _, err = verify()
	require.EqualError(t, err, "JWKS keys are older than MaximumKeyAge 24h0m0s and the last refetch failed")
	require.Nil(t, identity)
	require.Equal(t, int32(3), keySets.fetches.Load(), "no new attempt within a minute")

	clock.advance(time.Minute)
	keySets.serve(signer.JWKSHandler())
	identity, refreshError, err = verify()
	require.NoError(t, err)
	require.NoError(t, refreshError)
	require.Equal(t, "42", identity.Subject)
}

func TestVerifyFailsWhenTheRefetchForAnUnknownKeyIDFails(t *testing.T) {
	clock := &testClock{instant: signedAt}
	keySets := newKeySetServer(t, newTestSigner(t, clock.now).JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	keySets.serve(failingHandler)
	clock.advance(time.Minute)
	token, err := newTestSigner(t, clock.now).Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)

	identity, err := verifier.Verify(t.Context(), token)

	require.ErrorContains(t, err, "status 500")
	require.NotErrorIs(t, err, auth.ErrUnauthenticated)
	require.Nil(t, identity)
}

func TestVerifyDoesNotWaitForARefetchWithAKnownKeyID(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer, rotated := newTestSigner(t, clock.now), newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	fetchStarted, releaseFetch := make(chan struct{}), make(chan struct{})
	started, release := sync.OnceFunc(func() { close(fetchStarted) }), sync.OnceFunc(func() { close(releaseFetch) })
	defer release()
	rotatedKeys := keySetHandler(t, publishedKey(t, signer), publishedKey(t, rotated))
	keySets.serve(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started()
		<-releaseFetch
		rotatedKeys.ServeHTTP(writer, request)
	}))
	clock.advance(time.Minute)
	sign := func(signer *Signer) string {
		token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
		require.NoError(t, err)
		return token
	}
	unknownToken, knownToken, laterUnknownToken := sign(rotated), sign(signer), sign(rotated)

	unknownVerified := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(t.Context(), unknownToken)
		unknownVerified <- err
	}()
	<-fetchStarted
	knownVerified := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(t.Context(), knownToken)
		knownVerified <- err
	}()
	laterUnknownVerified := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(t.Context(), laterUnknownToken)
		laterUnknownVerified <- err
	}()

	select {
	case err := <-knownVerified:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		require.Fail(t, "a known key ID waited for the JWKS fetch")
	}
	release()
	require.NoError(t, <-unknownVerified, "the fetch brought the rotated key")
	require.NoError(t, <-laterUnknownVerified, "an unknown key ID during the fetch gets the fetched keys")
	require.Equal(t, int32(2), keySets.fetches.Load(), "one refetch for all")
}

func TestVerifyStopsWaitingForARefetchWhenTheRequestEnds(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer, rotated := newTestSigner(t, clock.now), newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	fetchStarted, releaseFetch := make(chan struct{}), make(chan struct{})
	started, release := sync.OnceFunc(func() { close(fetchStarted) }), sync.OnceFunc(func() { close(releaseFetch) })
	defer release()
	rotatedKeys := rotated.JWKSHandler()
	keySets.serve(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started()
		<-releaseFetch
		rotatedKeys.ServeHTTP(writer, request)
	}))
	clock.advance(time.Minute)
	token, err := rotated.Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)
	fetching := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(t.Context(), token)
		fetching <- err
	}()
	<-fetchStarted
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	waited := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(cancelled, token)
		waited <- err
	}()

	select {
	case err := <-waited:
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, auth.ErrUnauthenticated)
	case <-time.After(5 * time.Second):
		require.Fail(t, "a cancelled request waited for the JWKS fetch")
	}
	release()
	require.NoError(t, <-fetching, "the fetch goes on for its own request")
}

func TestVerifyIsSafeForConcurrentUse(t *testing.T) {
	clock := &testClock{instant: signedAt}
	signer := newTestSigner(t, clock.now)
	keySets := newKeySetServer(t, signer.JWKSHandler())
	verifier := newTestVerifier(t, testVerifierOptions(keySets.server.URL), clock)
	clock.advance(time.Hour)
	token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
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
	token, err := signer.Sign(&auth.Identity{Provider: "github", Subject: "42", Active: true})
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
		{name: "two spaces after the scheme", header: http.Header{"Authorization": {"Bearer  " + token}}, wantStatus: http.StatusOK, wantBody: "42", wantResult: auth.ResultSuccess},
		{name: "space after the token", header: http.Header{"Authorization": {"Bearer " + token + " "}}, wantStatus: http.StatusOK, wantBody: "42", wantResult: auth.ResultSuccess},
		{name: "only spaces after the scheme", header: http.Header{"Authorization": {"Bearer   "}}, wantStatus: http.StatusUnauthorized, wantBody: `{"code":"unauthenticated","message":"authentication required"}`, wantResult: auth.ResultDenied},
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
			if testCase.wantStatus == http.StatusUnauthorized {
				require.Equal(t, "Bearer", recorder.Header().Get("WWW-Authenticate"))
			} else {
				require.Empty(t, recorder.Header().Get("WWW-Authenticate"))
			}
			require.Len(t, outcomes, 1)
			require.Equal(t, auth.ProviderJWT, outcomes[0].Provider)
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
	token, err := newTestSigner(t, clock.now).Sign(&auth.Identity{Subject: "42", Active: true})
	require.NoError(t, err)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/items", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	verifier.Middleware()(subjectHandler()).ServeHTTP(recorder, request)

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.JSONEq(t, `{"code":"internal","message":"internal error"}`, recorder.Body.String())
	require.Empty(t, recorder.Header().Get("WWW-Authenticate"))
	require.Len(t, outcomes, 1)
	require.Equal(t, auth.ResultError, outcomes[0].Result)
	require.ErrorContains(t, outcomes[0].Err, "status 500")
}

func TestMiddlewareReportsAFailedRefresh(t *testing.T) {
	testCases := []struct {
		name       string
		sign       func(t *testing.T, signer *Signer, now time.Time) string
		wantStatus int
		wantBody   string
		wantResult auth.Result
		wantError  error // checked with ErrorIs when set
	}{
		{
			name: "valid token: degraded success",
			sign: func(t *testing.T, signer *Signer, _ time.Time) string {
				token, err := signer.Sign(&auth.Identity{Subject: "42", Active: true})
				require.NoError(t, err)
				return token
			},
			wantStatus: http.StatusOK, wantBody: "42", wantResult: auth.ResultSuccess,
		},
		{
			name: "refused token: refusal",
			sign: func(t *testing.T, signer *Signer, now time.Time) string {
				return signWith(t, signer, jwa.RS512(), withClaim(validClaims(now), "iss", "https://evil.example.com"))
			},
			wantStatus: http.StatusUnauthorized, wantBody: `{"code":"invalid_token","message":"authentication required"}`, wantResult: auth.ResultDenied, wantError: auth.ErrUnauthenticated,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			clock := &testClock{instant: signedAt}
			var outcomes []auth.Outcome
			signer := newTestSigner(t, clock.now)
			keySets := newKeySetServer(t, signer.JWKSHandler())
			options := testVerifierOptions(keySets.server.URL)
			options.Observer = func(_ context.Context, outcome auth.Outcome) { outcomes = append(outcomes, outcome) }
			verifier := newTestVerifier(t, options, clock)
			keySets.serve(failingHandler)
			clock.advance(time.Hour)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/items", nil)
			request.Header.Set("Authorization", "Bearer "+testCase.sign(t, signer, clock.now()))
			recorder := httptest.NewRecorder()

			verifier.Middleware()(subjectHandler()).ServeHTTP(recorder, request)

			require.Equal(t, testCase.wantStatus, recorder.Code)
			require.Equal(t, testCase.wantBody, strings.TrimSpace(recorder.Body.String()))
			require.Len(t, outcomes, 1)
			require.Equal(t, testCase.wantResult, outcomes[0].Result)
			if testCase.wantError != nil {
				require.ErrorIs(t, outcomes[0].Err, testCase.wantError)
			}
			require.ErrorContains(t, outcomes[0].Err, "status 500")
		})
	}
}
