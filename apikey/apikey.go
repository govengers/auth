package apikey

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/govengers/auth"
)

const (
	provider          = "apikey"
	defaultHeaderName = "X-API-Key"
	minimumSecretSize = 16
	bearerPrefix      = "Bearer "
)

// Key is one statically configured API key.
type Key struct {
	Name        string            // required, unique, non-empty; becomes Identity.Subject and Username
	Secret      string            // required, at least 16 bytes, no surrounding whitespace; SHA-256 pre-hashed at construction
	Roles       []string          // optional, e.g. auth.RoleAdmin
	Permissions []auth.Permission // optional, each valid (auth.Permission.Validate), e.g. "builds:write"; every identity of the key gets a copy
}

// Resolver resolves application-issued keys. Unknown or revoked: return an error matching
// auth.ErrUnauthenticated. A returned identity with empty Provider gets "apikey"; it carries its own
// Permissions (e.g. a stored read_only level becomes "*:read"). Any other error is
// answered as a 500, whatever its kind. It must be safe for concurrent use.
type Resolver func(ctx context.Context, key string) (*auth.Identity, error)

// Options configure an Authenticator.
type Options struct {
	Keys       []Key
	Resolver   Resolver // at least one of Keys and Resolver
	HeaderName string   // default "X-API-Key"; "Authorization: Bearer <key>" is always accepted too
	Observer   auth.Observer
}

type staticKey struct {
	hash [sha256.Size]byte
	name string
	// roles and permissions belong to the Authenticator; every identity gets its own copy.
	roles       []string
	permissions []auth.Permission
}

// Authenticator turns a presented API key into an auth.Identity. It is safe for concurrent use.
type Authenticator struct {
	keys       []staticKey
	resolver   Resolver
	headerName string
	observer   auth.Observer
}

// New validates options and returns an Authenticator. It does not modify options, and changing them
// afterwards has no effect.
func New(options *Options) (*Authenticator, error) {
	if options == nil {
		return nil, errors.New("apikey: options are required")
	}
	if len(options.Keys) == 0 && options.Resolver == nil {
		return nil, errors.New("apikey: at least one of Keys and Resolver is required")
	}
	headerName := options.HeaderName
	if headerName == "" {
		headerName = defaultHeaderName
	}
	if http.CanonicalHeaderKey(headerName) == "Authorization" {
		return nil, errors.New("apikey: HeaderName must not be Authorization, Bearer keys are always accepted")
	}
	keys, err := newStaticKeys(options.Keys)
	if err != nil {
		return nil, err
	}
	return &Authenticator{keys: keys, resolver: options.Resolver, headerName: headerName, observer: options.Observer}, nil
}

func newStaticKeys(keys []Key) ([]staticKey, error) {
	static := make([]staticKey, 0, len(keys))
	for index, key := range keys {
		if err := validateKey(key); err != nil {
			return nil, fmt.Errorf("apikey: key %d: %w", index, err)
		}
		hash := sha256.Sum256([]byte(key.Secret))
		if slices.ContainsFunc(static, func(other staticKey) bool { return other.name == key.Name || other.hash == hash }) {
			return nil, fmt.Errorf("apikey: key %d: name or secret is used by another key", index)
		}
		static = append(static, staticKey{hash: hash, name: key.Name, roles: slices.Clone(key.Roles), permissions: slices.Clone(key.Permissions)})
	}
	return static, nil
}

func validateKey(key Key) error {
	switch {
	case strings.TrimSpace(key.Name) == "":
		return errors.New("key name is required")
	case len(key.Secret) < minimumSecretSize:
		return fmt.Errorf("key secret is shorter than %d bytes", minimumSecretSize)
	case strings.TrimSpace(key.Secret) != key.Secret:
		return errors.New("key secret has leading or trailing whitespace")
	}
	for _, permission := range key.Permissions {
		if err := permission.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Middleware authenticates requests that carry a key and passes the others on untouched. A valid key
// puts its identity into the request context. An invalid key is answered with 401 JSON (code
// invalid_api_key) and never falls through to another authenticator; a Resolver failure is answered
// with 500. Mount it before a session.Guard, which passes requests that already carry an identity, and
// not in front of a jwt.Verifier middleware: both read "Authorization: Bearer". Every decision is
// reported to the Observer as Action authenticate.
func (a *Authenticator) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			key := a.presentedKey(request)
			if key == "" {
				next.ServeHTTP(writer, request)
				return
			}
			ctx := request.Context()
			identity, err := a.authenticate(ctx, key)
			a.report(ctx, identity, err)
			if err != nil {
				auth.WriteError(writer, err)
				return
			}
			next.ServeHTTP(writer, request.WithContext(auth.WithIdentity(ctx, identity)))
		})
	}
}

// presentedKey returns the key from HeaderName, else from "Authorization: Bearer", else "".
func (a *Authenticator) presentedKey(request *http.Request) string {
	if key := strings.TrimSpace(request.Header.Get(a.headerName)); key != "" {
		return key
	}
	if bearer, found := strings.CutPrefix(request.Header.Get("Authorization"), bearerPrefix); found {
		return strings.TrimSpace(bearer)
	}
	return ""
}

// authenticate returns the identity of key, or an error that WriteError answers: the invalid_api_key
// refusal, or a plain error for a failing Resolver.
func (a *Authenticator) authenticate(ctx context.Context, key string) (*auth.Identity, error) {
	if static := a.findStatic(key); static != nil {
		return static.identity(), nil
	}
	if a.resolver == nil {
		return nil, invalidKey(nil)
	}
	resolved, err := a.resolver(ctx, key)
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		return nil, invalidKey(err)
	case err != nil:
		return nil, fmt.Errorf("apikey: resolve key: %v", err) //nolint:errorlint // %v keeps the Resolver's error kind from picking the response status
	case resolved == nil:
		return nil, invalidKey(nil)
	}
	identity := resolved.Clone()
	if identity.Provider == "" {
		identity.Provider = provider
	}
	return identity, nil
}

// findStatic compares the hash of key with every static hash in constant time, without early exit.
func (a *Authenticator) findStatic(key string) *staticKey {
	hash := sha256.Sum256([]byte(key))
	var found *staticKey
	for index := range a.keys {
		if subtle.ConstantTimeCompare(hash[:], a.keys[index].hash[:]) == 1 {
			found = &a.keys[index]
		}
	}
	return found
}

func (k *staticKey) identity() *auth.Identity {
	return &auth.Identity{
		Provider:    provider,
		Subject:     k.name,
		Username:    k.name,
		Active:      true,
		Roles:       slices.Clone(k.roles),
		Permissions: slices.Clone(k.permissions),
	}
}

func invalidKey(cause error) error {
	return &auth.Error{Kind: auth.ErrUnauthenticated, Code: "invalid_api_key", Err: cause}
}

func (a *Authenticator) report(ctx context.Context, identity *auth.Identity, err error) {
	if a.observer == nil {
		return
	}
	a.observer(ctx, auth.Outcome{
		Provider: provider,
		Action:   auth.ActionAuthenticate,
		Result:   resultOf(err),
		Err:      err,
		Identity: identity,
	})
}

func resultOf(err error) auth.Result {
	switch {
	case err == nil:
		return auth.ResultSuccess
	case errors.Is(err, auth.ErrUnauthenticated):
		return auth.ResultDenied
	default:
		return auth.ResultError
	}
}
