package jwt

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

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/internal/failure"
)

const (
	defaultRefreshInterval = time.Hour
	minimumFetchSpacing    = time.Minute
	clockSkew              = 30 * time.Second
	defaultHTTPTimeout     = 10 * time.Second
	defaultHeaderName      = "Authorization"
	maximumKeySetBytes     = 1 << 20
	providerName           = "jwt" // Outcome.Provider of the verifier's outcomes
	codeInvalidToken       = "invalid_token"
)

// VerifierOptions configure a Verifier.
type VerifierOptions struct {
	JWKSURL         string        // required: absolute http(s) URL of the signer's JWKS (at most 1 MiB); only its RSA keys with an RSA signature alg (RS*, PS*) and use "sig" (or none) count
	Issuer          string        // required: expected iss
	Audience        string        // optional: when set, aud must contain it
	RefreshInterval time.Duration // default 1 h, at least 1 min; an unknown kid triggers a refetch at most once per minute
	HTTPClient      *http.Client  // default 10 s timeout
	HeaderName      string        // default "Authorization", value "Bearer <token>"
	Observer        auth.Observer // optional; Middleware reports one ActionAuthenticate outcome per request
}

// Verifier checks RS512 tokens against a JWKS URL and turns them into identities. It keeps no token
// cache and starts no goroutine: Verify refetches the JWKS lazily, after RefreshInterval or for an
// unknown key ID, at most once per minute; the refetch is not cancelled with the triggering request and
// takes at most 10 s. Meanwhile verifications with a known key ID go on with the current keys, those
// with an unknown one wait for it. It is safe for concurrent use.
type Verifier struct {
	options VerifierOptions
	now     func() time.Time

	mutex       sync.Mutex // guards the fields below; never held during a JWKS fetch
	keys        jwk.Set
	fetchedAt   time.Time     // last successful fetch
	attemptedAt time.Time     // last fetch, successful or not
	fetchDone   chan struct{} // closed when the fetch in flight ends; nil without one
}

// NewVerifier fetches the JWKS once and fails when it cannot (fail fast). ctx bounds that fetch only.
func NewVerifier(ctx context.Context, options *VerifierOptions) (*Verifier, error) {
	resolved, err := resolveVerifierOptions(options)
	if err != nil {
		return nil, err
	}
	verifier := &Verifier{options: resolved, now: time.Now}
	if _, err := verifier.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("new JWT verifier: %w", err)
	}
	return verifier, nil
}

func resolveVerifierOptions(options *VerifierOptions) (VerifierOptions, error) {
	if options == nil {
		return VerifierOptions{}, errors.New("new JWT verifier: options are required")
	}
	resolved := *options
	if err := validateJWKSURL(resolved.JWKSURL); err != nil {
		return VerifierOptions{}, fmt.Errorf("new JWT verifier: %w", err)
	}
	if resolved.Issuer == "" {
		return VerifierOptions{}, errors.New("new JWT verifier: Issuer is required")
	}
	if resolved.RefreshInterval == 0 {
		resolved.RefreshInterval = defaultRefreshInterval
	}
	if resolved.RefreshInterval < minimumFetchSpacing {
		return VerifierOptions{}, fmt.Errorf("new JWT verifier: RefreshInterval %s is below %s", resolved.RefreshInterval, minimumFetchSpacing)
	}
	if resolved.HTTPClient == nil {
		resolved.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if resolved.HeaderName == "" {
		resolved.HeaderName = defaultHeaderName
	}
	return resolved, nil
}

// validateJWKSURL checks jwksURL. Its errors never quote user info or query, which may carry credentials.
func validateJWKSURL(jwksURL string) error {
	parsed, err := url.Parse(jwksURL)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err // without the URL
		}
		return fmt.Errorf("JWKSURL is no URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("JWKSURL %s must be an absolute http or https URL", redactedURL(parsed))
	}
	return nil
}

// redactedURL is location without user info, query and fragment, for error messages [LOG-009].
func redactedURL(location *url.URL) string {
	return (&url.URL{Scheme: location.Scheme, Host: location.Host, Path: location.Path}).String()
}

// Verify checks the token's signature (with the JWKS key named by its kid, under the key's algorithm),
// iss, aud, exp (required), nbf and iat with 30 s clock skew, and returns the identity it carries: Active,
// the fields of the package claim table and Claims = all claims of the token. Claims of the wrong type
// are skipped. An invalid token is an *auth.Error{Kind: auth.ErrUnauthenticated, Code: "invalid_token"};
// a failed JWKS fetch for an unknown kid is a plain error. A failed periodic refresh keeps the previous
// keys (Middleware reports it as a degraded outcome).
func (v *Verifier) Verify(ctx context.Context, token string) (*auth.Identity, error) {
	// The refresh error is survived with the previous keys; Verify has no channel for it, Middleware reports it.
	identity, _, err := v.verify(ctx, token)
	return identity, err
}

// verify is Verify that also returns the error of a failed periodic refresh it survived with the previous
// keys, whether the token then verifies or not.
func (v *Verifier) verify(ctx context.Context, token string) (identity *auth.Identity, refreshError, err error) {
	keyID, err := keyIDOf(token)
	if err != nil {
		return nil, nil, invalidToken(err.Error())
	}
	keys, refreshError, err := v.keysFor(ctx, keyID)
	if err != nil {
		return nil, nil, err
	}
	if _, found := keys.LookupKeyID(keyID); !found {
		return nil, nil, invalidToken("unknown key ID")
	}
	parsed, err := jwxjwt.ParseString(token, v.parseOptions(keys)...)
	if err != nil {
		return nil, refreshError, invalidToken(invalidTokenReason(err))
	}
	claims, err := claimsOf(parsed)
	if err != nil {
		return nil, refreshError, err
	}
	return identityFromClaims(claims), refreshError, nil
}

// keyIDOf returns the kid of the token's protected header. Its errors are fixed texts: the dependency's
// message may quote token material.
func keyIDOf(token string) (string, error) {
	message, err := jws.ParseString(token, jws.WithCompact())
	// The compact serialization carries exactly one signature; the length check only guards the index.
	if err != nil || len(message.Signatures()) != 1 {
		return "", errors.New("malformed token")
	}
	keyID, _ := message.Signatures()[0].ProtectedHeaders().KeyID()
	if keyID == "" {
		return "", errors.New("token header has no kid")
	}
	return keyID, nil
}

// keysFor returns the keys to verify a token with key ID keyID, refetching them first when they are
// stale or lack keyID and the last fetch is at least a minute ago. A failed refetch is err when the
// keys lack keyID, and refreshError (the previous keys are returned) when they have it.
func (v *Verifier) keysFor(ctx context.Context, keyID string) (keys jwk.Set, refreshError, err error) {
	keys, known, fetchDone := v.claimFetch(keyID)
	if fetchDone == nil {
		return keys, nil, nil
	}
	defer v.endFetch(fetchDone)
	// The fetch serves every verification waiting for it and uses up the minute's attempt, so the
	// triggering request's cancellation must not end it; it gets its own timeout instead [CON-003].
	fetchContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultHTTPTimeout)
	defer cancel()
	keys, fetchError := v.refreshKeys(fetchContext)
	switch {
	case fetchError == nil:
		return keys, nil, nil
	case known:
		return keys, fetchError, nil
	default:
		return nil, nil, fetchError
	}
}

// claimFetch returns the current keys and whether they have keyID. When a fetch is due it claims it and
// returns a non-nil fetchDone: the caller fetches without the mutex and ends the claim with endFetch.
// While a fetch is in flight, a known keyID goes on with the current keys and an unknown one waits for
// the fetch (at most 10 s), which may bring it.
func (v *Verifier) claimFetch(keyID string) (keys jwk.Set, known bool, fetchDone chan struct{}) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	_, known = v.keys.LookupKeyID(keyID)
	for v.fetchDone != nil && !known {
		inFlight := v.fetchDone
		v.mutex.Unlock()
		<-inFlight
		v.mutex.Lock()
		_, known = v.keys.LookupKeyID(keyID)
	}
	if v.fetchDone != nil || !v.fetchDue(known) {
		return v.keys, known, nil
	}
	v.fetchDone = make(chan struct{})
	return v.keys, known, v.fetchDone
}

// endFetch ends the fetch claimed with fetchDone and wakes the verifications waiting for it.
func (v *Verifier) endFetch(fetchDone chan struct{}) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	v.fetchDone = nil
	close(fetchDone)
}

func (v *Verifier) fetchDue(keyKnown bool) bool {
	now := v.now()
	stale := now.Sub(v.fetchedAt) >= v.options.RefreshInterval
	return (stale || !keyKnown) && now.Sub(v.attemptedAt) >= minimumFetchSpacing
}

// refreshKeys fetches the JWKS without the mutex, replaces the keys on success and returns the keys after
// the attempt. The caller has claimed the fetch (claimFetch) or owns the verifier exclusively, as
// NewVerifier does.
func (v *Verifier) refreshKeys(ctx context.Context) (jwk.Set, error) {
	attemptedAt := v.now()
	fetched, err := fetchKeySet(ctx, v.options.HTTPClient, v.options.JWKSURL)
	v.mutex.Lock()
	defer v.mutex.Unlock()
	v.attemptedAt = attemptedAt
	if err == nil {
		v.keys, v.fetchedAt = fetched, attemptedAt
	}
	return v.keys, err
}

func fetchKeySet(ctx context.Context, httpClient *http.Client, jwksURL string) (jwk.Set, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}
	location := redactedURL(request.URL)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, dependency.Error("fetch JWKS", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS %s: status %d", location, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumKeySetBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JWKS %s: %w", location, err)
	}
	if len(body) > maximumKeySetBytes {
		return nil, fmt.Errorf("JWKS %s is larger than 1 MiB", location)
	}
	// An entry jwx cannot parse (an unknown kty, a broken modulus) is dropped like the other keys that
	// cannot verify a token, instead of failing the whole set; signingKeys fails when none is left.
	keys, err := jwk.Parse(body, jwk.WithIgnoreParseError(true))
	if err != nil {
		return nil, dependency.Error("parse JWKS "+location, err)
	}
	return signingKeys(keys)
}

// signingKeys returns the keys of keys a token may be verified with: RSA keys for signatures (use "sig"
// or unset) that name an RSA signature algorithm. A JWKS is public, so a symmetric key in it would let
// anyone sign tokens; a key without alg cannot bind the token's algorithm, and one with another alg
// verifies no token.
func signingKeys(keys jwk.Set) (jwk.Set, error) {
	usable := jwk.NewSet()
	for index := range keys.Len() {
		key, _ := keys.Key(index)
		usage, _ := key.KeyUsage()
		if key.KeyType() != jwa.RSA() || (usage != "" && usage != string(jwk.ForSignature)) || !hasRSASignatureAlgorithm(key) {
			continue
		}
		if err := usable.AddKey(key); err != nil {
			return nil, dependency.Error("keep JWKS key", err)
		}
	}
	if usable.Len() == 0 {
		return nil, errors.New("JWKS has no RSA signing key with alg")
	}
	return usable, nil
}

// hasRSASignatureAlgorithm reports whether key names an algorithm RSA keys sign with (RFC 7518 section 3.1).
func hasRSASignatureAlgorithm(key jwk.Key) bool {
	algorithm, found := key.Algorithm()
	return found && slices.Contains([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, algorithm.String())
}

func (v *Verifier) parseOptions(keys jwk.Set) []jwxjwt.ParseOption {
	options := []jwxjwt.ParseOption{
		jwxjwt.WithKeySet(keys),
		jwxjwt.WithIssuer(v.options.Issuer),
		jwxjwt.WithRequiredClaim(jwxjwt.ExpirationKey),
		jwxjwt.WithAcceptableSkew(clockSkew),
		jwxjwt.WithClock(jwxjwt.ClockFunc(v.now)),
	}
	if v.options.Audience != "" {
		options = append(options, jwxjwt.WithAudience(v.options.Audience))
	}
	return options
}

// claimsOf returns the claims of a verified token as JSON values (numbers are float64).
func claimsOf(token jwxjwt.Token) (map[string]any, error) {
	payload, err := json.Marshal(token)
	if err != nil {
		return nil, dependency.Error("encode verified claims", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode verified claims: %w", err)
	}
	return claims, nil
}

// invalidToken is the refusal of an invalid token. reason is a fixed text (it goes into the wide event)
// and never reaches the client.
func invalidToken(reason string) error {
	return &auth.Error{Kind: auth.ErrUnauthenticated, Code: codeInvalidToken, Reason: reason}
}

// invalidTokenReason names why jwx refused a token. jwx's message quotes token material (the kid,
// claim values) of any length, so it never becomes the Reason [LOG-009].
func invalidTokenReason(err error) string {
	switch {
	case errors.Is(err, jws.VerificationError()):
		return "signature invalid"
	case errors.Is(err, jwxjwt.TokenExpiredError()):
		return "token expired"
	case errors.Is(err, jwxjwt.TokenNotYetValidError()):
		return "token not yet valid"
	case errors.Is(err, jwxjwt.InvalidIssuedAtError()):
		return "token issued in the future"
	case errors.Is(err, jwxjwt.InvalidIssuerError()):
		return "issuer mismatch"
	case errors.Is(err, jwxjwt.InvalidAudienceError()):
		return "audience mismatch"
	case errors.Is(err, jwxjwt.MissingRequiredClaimError()):
		return "expiry missing"
	default:
		return "token invalid"
	}
}

// Middleware requires a valid token in HeaderName ("Bearer <token>"): the identity goes into the request
// context, a missing or invalid token is answered 401 JSON with WWW-Authenticate: Bearer (RFC 6750), a
// failed JWKS fetch 500. It reports one ActionAuthenticate outcome per request to the Observer.
func (v *Verifier) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			ctx := request.Context()
			identity, refreshError, err := v.authenticate(ctx, request.Header.Get(v.options.HeaderName))
			v.report(ctx, outcomeOf(identity, refreshError, err))
			if err != nil {
				if status, _ := auth.ResponseFor(err); status == http.StatusUnauthorized {
					writer.Header().Set("WWW-Authenticate", "Bearer")
				}
				auth.WriteError(writer, err)
				return
			}
			next.ServeHTTP(writer, request.WithContext(auth.WithIdentity(ctx, identity)))
		})
	}
}

func (v *Verifier) authenticate(ctx context.Context, headerValue string) (identity *auth.Identity, refreshError, err error) {
	token, ok := bearerToken(headerValue)
	if !ok {
		return nil, nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "no bearer token in header " + v.options.HeaderName}
	}
	return v.verify(ctx, token)
}

// bearerToken returns the token of a "Bearer <token>" header value; the scheme matches case-insensitively
// and spaces around the token are allowed (RFC 9110 section 11.4: 1*SP).
func bearerToken(headerValue string) (string, bool) {
	scheme, token, found := strings.Cut(headerValue, " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// outcomeOf is the outcome of one authentication. A failed refresh is the Err of a success (degraded) and
// joins the refusal or failure otherwise, so it is reported either way.
func outcomeOf(identity *auth.Identity, refreshError, err error) auth.Outcome {
	outcome := auth.Outcome{Provider: providerName, Action: auth.ActionAuthenticate, Result: auth.ResultSuccess, Err: refreshError, Identity: identity}
	if err != nil {
		outcome.Result, outcome.Err = failure.Result(err), err
		if refreshError != nil {
			outcome.Err = errors.Join(err, refreshError)
		}
	}
	return outcome
}

func (v *Verifier) report(ctx context.Context, outcome auth.Outcome) {
	if v.options.Observer != nil {
		v.options.Observer(ctx, outcome)
	}
}
