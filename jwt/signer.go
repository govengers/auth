package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/dependency"
)

const (
	defaultLifetime     = 5 * time.Minute
	notBeforeBackdating = 30 * time.Second
	minimumKeyBits      = 2048
)

// SignerOptions configure a Signer.
type SignerOptions struct {
	PrivateKey []byte        // required: PEM RSA private key, PKCS#1 or PKCS#8, at least 2048 bits
	Issuer     string        // required: iss of every token, also what verifiers expect
	Audience   []string      // optional aud
	Lifetime   time.Duration // default 5 min
}

// Signer mints RS512 tokens for identities and serves its public key as a JWKS. It is safe for
// concurrent use.
type Signer struct {
	options    SignerOptions // PrivateKey is not kept
	signingKey jwk.Key
	keySetJSON []byte
	now        func() time.Time
}

// NewSigner parses the private key and precomputes the JWKS. The key ID is the RFC 7638 SHA-256
// thumbprint of the public key, so it is stable across restarts and replicas sharing the key.
func NewSigner(options *SignerOptions) (*Signer, error) {
	resolved, err := resolveSignerOptions(options)
	if err != nil {
		return nil, err
	}
	privateKey, err := parsePrivateKey(resolved.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("new JWT signer: %w", err)
	}
	keyID, keySetJSON, err := publicKeySet(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("new JWT signer: %w", err)
	}
	signingKey, err := jwkWithKeyID(privateKey, keyID)
	if err != nil {
		return nil, fmt.Errorf("new JWT signer: %w", err)
	}
	resolved.PrivateKey = nil
	return &Signer{options: resolved, signingKey: signingKey, keySetJSON: keySetJSON, now: time.Now}, nil
}

func resolveSignerOptions(options *SignerOptions) (SignerOptions, error) {
	if options == nil {
		return SignerOptions{}, errors.New("new JWT signer: options are required")
	}
	resolved := *options
	resolved.Audience = slices.Clone(options.Audience)
	if resolved.Issuer == "" {
		return SignerOptions{}, errors.New("new JWT signer: Issuer is required")
	}
	if resolved.Lifetime < 0 {
		return SignerOptions{}, fmt.Errorf("new JWT signer: Lifetime %s is negative", resolved.Lifetime)
	}
	if resolved.Lifetime == 0 {
		resolved.Lifetime = defaultLifetime
	}
	return resolved, nil
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("PrivateKey holds no PEM block")
	}
	privateKey, err := parseRSAPrivateKey(block)
	if err != nil {
		return nil, err
	}
	if bits := privateKey.N.BitLen(); bits < minimumKeyBits {
		return nil, fmt.Errorf("RSA private key has %d bits, at least %d are required", bits, minimumKeyBits)
	}
	return privateKey, nil
}

func parseRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 private key: %w", err)
		}
		return privateKey, nil
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 private key is a %T, not an RSA key", privateKey)
		}
		return rsaPrivateKey, nil
	default:
		return nil, fmt.Errorf("PEM block %q is neither a PKCS#1 nor a PKCS#8 private key", block.Type)
	}
}

// publicKeySet returns the key ID (RFC 7638 SHA-256 thumbprint) and the JWKS document of publicKey.
func publicKeySet(publicKey *rsa.PublicKey) (keyID string, keySetJSON []byte, err error) {
	thumbprintKey, err := jwk.Import(publicKey)
	if err != nil {
		return "", nil, dependency.Error("import public key", err)
	}
	thumbprint, err := thumbprintKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", nil, dependency.Error("compute key thumbprint", err)
	}
	keyID = base64.RawURLEncoding.EncodeToString(thumbprint)
	publicJWK, err := jwkWithKeyID(publicKey, keyID)
	if err != nil {
		return "", nil, err
	}
	for name, value := range map[string]any{jwk.AlgorithmKey: jwa.RS512(), jwk.KeyUsageKey: jwk.ForSignature} {
		if err := publicJWK.Set(name, value); err != nil {
			return "", nil, dependency.Error("set JWK "+name, err)
		}
	}
	keySetJSON, err = json.Marshal(map[string][]jwk.Key{"keys": {publicJWK}})
	if err != nil {
		return "", nil, dependency.Error("encode JWKS", err)
	}
	return keyID, keySetJSON, nil
}

func jwkWithKeyID(rawKey any, keyID string) (jwk.Key, error) {
	key, err := jwk.Import(rawKey)
	if err != nil {
		return nil, dependency.Error(fmt.Sprintf("import %T", rawKey), err)
	}
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, dependency.Error("set key ID", err)
	}
	return key, nil
}

// Sign mints an RS512 token for identity: header kid and typ JWT; claims iss, aud, iat, nbf (now - 30 s),
// exp (now + Lifetime), a random jti, the identity's fields and every other key of its Claims (see the
// package claim table). An invalid permission is an error; an inactive identity is refused with
// auth.ErrForbidden (Reason auth.ReasonInactive), since Verify returns every identity as active. It does not
// modify identity.
func (s *Signer) Sign(identity *auth.Identity) (string, error) {
	if identity == nil {
		return "", errors.New("sign JWT: identity is nil")
	}
	if !identity.Active {
		return "", &auth.Error{Kind: auth.ErrForbidden, Reason: auth.ReasonInactive}
	}
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return "", dependency.Error("sign JWT: generate token ID", err)
	}
	claims, err := identityClaims(identity)
	if err != nil {
		return "", fmt.Errorf("sign JWT for subject %s: %w", identity.Subject, err)
	}
	maps.Copy(claims, s.registeredClaims(tokenID))
	token := jwxjwt.New()
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			return "", dependency.Error("sign JWT: set claim "+name, err)
		}
	}
	signed, err := jwxjwt.Sign(token, jwxjwt.WithKey(jwa.RS512(), s.signingKey))
	if err != nil {
		return "", dependency.Error("sign JWT for subject "+identity.Subject, err)
	}
	return string(signed), nil
}

func (s *Signer) registeredClaims(tokenID uuid.UUID) map[string]any {
	issuedAt := s.now()
	claims := map[string]any{
		jwxjwt.IssuerKey:     s.options.Issuer,
		jwxjwt.IssuedAtKey:   issuedAt.Unix(),
		jwxjwt.NotBeforeKey:  issuedAt.Add(-notBeforeBackdating).Unix(),
		jwxjwt.ExpirationKey: issuedAt.Add(s.options.Lifetime).Unix(),
		jwxjwt.JwtIDKey:      tokenID.String(),
	}
	if len(s.options.Audience) > 0 {
		claims[jwxjwt.AudienceKey] = slices.Clone(s.options.Audience)
	}
	return claims
}

// JWKSHandler serves the public key as {"keys":[{kty,n,e,kid,alg:"RS512",use:"sig"}]} with
// Cache-Control: public, max-age=300. The document is computed once by NewSigner.
func (s *Signer) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "public, max-age=300")
		writer.WriteHeader(http.StatusOK)
		// A write error means the client is gone and there is nobody left to answer.
		_, _ = writer.Write(s.keySetJSON)
	})
}
