package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

const testIssuer = "https://auth.example.com"

var signedAt = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func generateKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return privateKey
}

func pkcs1PEM(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}

func pkcs8PEM(t *testing.T, privateKey any) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

// newTestSigner returns a signer for testIssuer and audience "backend" whose clock reads now().
func newTestSigner(t *testing.T, now func() time.Time) *Signer {
	t.Helper()
	signer, err := NewSigner(&SignerOptions{PrivateKey: pkcs1PEM(generateKey(t, 2048)), Issuer: testIssuer, Audience: []string{"backend"}})
	require.NoError(t, err)
	signer.now = now
	return signer
}

func fixedClock(instant time.Time) func() time.Time {
	return func() time.Time { return instant }
}

// payloadOf returns the claims of a compact token without verifying it.
func payloadOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func TestNewSignerRejectsInvalidOptions(t *testing.T) {
	validKey := pkcs1PEM(generateKey(t, 2048))
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	testCases := []struct {
		name      string
		options   *SignerOptions
		wantError string
	}{
		{name: "nil options", options: nil, wantError: "options are required"},
		{name: "missing issuer", options: &SignerOptions{PrivateKey: validKey}, wantError: "Issuer is required"},
		{name: "negative lifetime", options: &SignerOptions{PrivateKey: validKey, Issuer: testIssuer, Lifetime: -time.Second}, wantError: "Lifetime -1s is negative"},
		{name: "missing key", options: &SignerOptions{Issuer: testIssuer}, wantError: "no PEM block"},
		{name: "not PEM", options: &SignerOptions{PrivateKey: []byte("not a key"), Issuer: testIssuer}, wantError: "no PEM block"},
		{name: "wrong block type", options: &SignerOptions{PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), Issuer: testIssuer}, wantError: `PEM block "CERTIFICATE"`},
		{name: "broken PKCS#1", options: &SignerOptions{PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}), Issuer: testIssuer}, wantError: "parse PKCS#1"},
		{name: "broken PKCS#8", options: &SignerOptions{PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), Issuer: testIssuer}, wantError: "parse PKCS#8"},
		{name: "PKCS#8 ECDSA key", options: &SignerOptions{PrivateKey: pkcs8PEM(t, ecdsaKey), Issuer: testIssuer}, wantError: "not an RSA key"},
		{name: "1024 bit key", options: &SignerOptions{PrivateKey: pkcs1PEM(generateKey(t, 1024)), Issuer: testIssuer}, wantError: "has 1024 bits, at least 2048"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			signer, err := NewSigner(testCase.options)
			require.ErrorContains(t, err, testCase.wantError)
			require.Nil(t, signer)
		})
	}
}

func TestNewSignerAcceptsPKCS1AndPKCS8WithOneKeyID(t *testing.T) {
	privateKey := generateKey(t, 2048)
	var keySets []string
	for _, privateKeyPEM := range [][]byte{pkcs1PEM(privateKey), pkcs8PEM(t, privateKey), pkcs1PEM(privateKey)} {
		signer, err := NewSigner(&SignerOptions{PrivateKey: privateKeyPEM, Issuer: testIssuer})
		require.NoError(t, err)
		keySets = append(keySets, string(signer.keySetJSON))
	}
	require.Equal(t, keySets[0], keySets[1])
	require.Equal(t, keySets[0], keySets[2])
}

func TestNewSignerLeavesOptionsUntouched(t *testing.T) {
	privateKeyPEM := pkcs1PEM(generateKey(t, 2048))
	options := &SignerOptions{PrivateKey: privateKeyPEM, Issuer: testIssuer, Audience: []string{"backend"}}

	signer, err := NewSigner(options)
	require.NoError(t, err)
	options.Audience[0] = "changed"

	require.Equal(t, &SignerOptions{PrivateKey: privateKeyPEM, Issuer: testIssuer, Audience: []string{"changed"}}, options)
	require.Equal(t, SignerOptions{Issuer: testIssuer, Audience: []string{"backend"}, Lifetime: 5 * time.Minute}, signer.options)
}

func TestJWKSHandlerServesThePublicKeyOnly(t *testing.T) {
	privateKey := generateKey(t, 2048)
	signer, err := NewSigner(&SignerOptions{PrivateKey: pkcs1PEM(privateKey), Issuer: testIssuer})
	require.NoError(t, err)
	recorder := httptest.NewRecorder()

	signer.JWKSHandler().ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/jwks", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	require.Equal(t, "public, max-age=300", recorder.Header().Get("Cache-Control"))
	var keySet struct {
		Keys []map[string]string `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &keySet))
	require.Len(t, keySet.Keys, 1)
	key := keySet.Keys[0]
	modulus := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())
	require.Equal(t, map[string]string{
		"kty": "RSA",
		"n":   modulus,
		"e":   exponent,
		"kid": rfc7638Thumbprint(t, exponent, modulus),
		"alg": "RS512",
		"use": "sig",
	}, key)
}

// rfc7638Thumbprint computes the SHA-256 JWK thumbprint of an RSA key by the RFC's recipe, independent
// of jwx: the required members in lexicographic order, no whitespace.
func rfc7638Thumbprint(t *testing.T, exponent, modulus string) string {
	t.Helper()
	canonical := `{"e":"` + exponent + `","kty":"RSA","n":"` + modulus + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestSignWritesHeaderAndRegisteredClaims(t *testing.T) {
	signer := newTestSigner(t, fixedClock(signedAt))

	token, err := signer.Sign(&auth.Identity{Provider: "github", Subject: "42", Active: true})
	require.NoError(t, err)

	message, err := jws.ParseString(token)
	require.NoError(t, err)
	headers := message.Signatures()[0].ProtectedHeaders()
	algorithm, _ := headers.Algorithm()
	require.Equal(t, jwa.RS512(), algorithm)
	keyID, _ := headers.KeyID()
	wantKeyID, _ := signer.signingKey.KeyID()
	require.Equal(t, wantKeyID, keyID)
	tokenType, _ := headers.Type()
	require.Equal(t, "JWT", tokenType)

	claims := payloadOf(t, token)
	_, err = uuid.Parse(claims["jti"].(string))
	require.NoError(t, err)
	delete(claims, "jti")
	require.Equal(t, map[string]any{
		"iss":      testIssuer,
		"aud":      []any{"backend"},
		"sub":      "42",
		"provider": "github",
		"iat":      float64(signedAt.Unix()),
		"nbf":      float64(signedAt.Add(-30 * time.Second).Unix()),
		"exp":      float64(signedAt.Add(5 * time.Minute).Unix()),
	}, claims)
}

func TestSignUsesAFreshTokenIDAndLeavesTheIdentityUntouched(t *testing.T) {
	signer := newTestSigner(t, fixedClock(signedAt))
	identity := &auth.Identity{Subject: "42", Active: true, Roles: []string{"reader"}, Claims: map[string]any{"iss": "https://idp.example.com", "locale": "de"}}

	first, err := signer.Sign(identity)
	require.NoError(t, err)
	second, err := signer.Sign(identity)
	require.NoError(t, err)

	require.NotEqual(t, payloadOf(t, first)["jti"], payloadOf(t, second)["jti"])
	require.Equal(t, &auth.Identity{Subject: "42", Active: true, Roles: []string{"reader"}, Claims: map[string]any{"iss": "https://idp.example.com", "locale": "de"}}, identity)
}

func TestSignRefuses(t *testing.T) {
	testCases := []struct {
		name      string
		identity  *auth.Identity
		wantError string
	}{
		{name: "nil identity", wantError: "identity is nil"},
		{name: "invalid permission", identity: &auth.Identity{Subject: "42", Active: true, Permissions: []auth.Permission{{Resource: "builds", Access: "admin"}}}, wantError: "sign JWT for subject 42: permissions claim"},
		{name: "claims that do not encode", identity: &auth.Identity{Subject: "42", Active: true, Claims: map[string]any{"channel": make(chan int)}}, wantError: "sign JWT for subject 42"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			signer := newTestSigner(t, fixedClock(signedAt))

			token, err := signer.Sign(testCase.identity)

			require.ErrorContains(t, err, testCase.wantError)
			require.Empty(t, token)
		})
	}
}

func TestSignRefusesAnInactiveIdentity(t *testing.T) {
	signer := newTestSigner(t, fixedClock(signedAt))

	token, err := signer.Sign(&auth.Identity{Subject: "42", Roles: []string{auth.RoleAdmin}, Permissions: []auth.Permission{{Resource: auth.AllResources, Access: auth.AccessWrite}}})

	require.ErrorIs(t, err, auth.ErrForbidden, "Verify would return the identity as active, privileges and all")
	status, _ := auth.ResponseFor(err)
	require.Equal(t, http.StatusForbidden, status)
	require.Empty(t, token)
}
