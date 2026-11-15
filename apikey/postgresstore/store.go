package postgresstore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/internal/random"
)

const (
	defaultLastUsedInterval = time.Minute
	secretBytes             = 32
	secretLength            = 43 // base64url without padding of secretBytes
	idLength                = 32 // the key ID as lower-case hex without dashes
	maximumNameBytes        = 200
)

// prefixPattern keeps the prefix recognizable for secret scanners and free of the separators "_" and ".".
var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)

// fullAccess is the scope that leaves the owner's identity whole, roles included.
var fullAccess = auth.Permission{Resource: auth.AllResources, Access: auth.AccessWrite}

// ErrKeyNotFound is returned by Revoke when the owner has no key with the ID.
var ErrKeyNotFound = errors.New("api key not found")

const insertKey = `
INSERT INTO govengers_auth_api_keys (id, owner_id, name, secret_hash, scopes, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

const selectKeys = `
SELECT id, owner_id, name, scopes, created_at, expires_at, last_used_at
FROM govengers_auth_api_keys WHERE owner_id = $1 ORDER BY created_at, id`

const deleteKey = `DELETE FROM govengers_auth_api_keys WHERE owner_id = $1 AND id = $2`

const selectKeyForResolve = `
SELECT owner_id, secret_hash, scopes, expires_at, last_used_at FROM govengers_auth_api_keys WHERE id = $1`

// touchKey records a use at most once per interval: of concurrent requests only the first writes.
const touchKey = `
UPDATE govengers_auth_api_keys SET last_used_at = $2
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at <= $3)`

// Loader returns the identity of a key's owner, called for every request a key authenticates. Return an
// error matching auth.ErrUnauthenticated for an owner that no longer exists; set Active as for a session
// login (an inactive identity is refused by every check but IsAuthenticated). It must be safe for
// concurrent use.
type Loader func(ctx context.Context, ownerID uuid.UUID) (*auth.Identity, error)

// Options configures New.
type Options struct {
	Pool *pgxpool.Pool // required; its search_path must reach the table of MigrationV1; the caller owns and closes it
	// Prefix starts every key, "<Prefix>_<id>.<secret>", so secret scanners and people recognize it:
	// required, a lower-case letter, then 1 to 15 lower-case letters or digits (e.g. "todo").
	Prefix string
	Load   Loader // required
	// LastUsedInterval is how stale LastUsedAt may get before a use writes it again (default 1 minute), so a
	// busy key costs one write per interval, not one per request.
	LastUsedInterval time.Duration
}

// Key is an issued API key without its secret.
type Key struct {
	ID         uuid.UUID
	OwnerID    uuid.UUID
	Name       string
	Scopes     []auth.Permission
	CreatedAt  time.Time
	ExpiresAt  time.Time // zero: never expires
	LastUsedAt time.Time // zero: never used; up to LastUsedInterval behind the last use
}

// IssueRequest describes a key to issue.
type IssueRequest struct {
	Name      string            // required, at most 200 bytes, for the owner's list
	Scopes    []auth.Permission // required, each valid; they cap the owner's permissions (see Store)
	ExpiresAt time.Time         // zero: never expires; otherwise in the future
}

// Store issues, lists and revokes per-owner API keys in PostgreSQL and resolves presented keys for an
// apikey.Authenticator. A key is "<Prefix>_<id>.<secret>": id is the key's UUID in hex, secret 32 random
// bytes in base64url; the table holds the SHA-256 of the secret only. It is safe for concurrent use.
//
// A resolved key acts as its owner (Load) narrowed to its scopes: the identity's Permissions become those
// both the owner's permissions and the key's scopes grant, and a key without the scope "*:write" also drops
// the owner's Roles, OIDCRoles, OIDCClientRoles, Groups and Teams, which no resource scope can narrow.
// Provider is "apikey", Subject the key ID, UserID the owner's (Load's, else the owner ID), and the
// identity never impersonates.
type Store struct {
	pool             *pgxpool.Pool
	prefix           string
	load             Loader
	lastUsedInterval time.Duration
	now              func() time.Time
}

// New validates options and returns a Store.
func New(options *Options) (*Store, error) {
	switch {
	case options == nil || options.Pool == nil:
		return nil, errors.New("postgres api key store: Options.Pool is required")
	case options.Load == nil:
		return nil, errors.New("postgres api key store: Options.Load is required")
	case !prefixPattern.MatchString(options.Prefix):
		return nil, fmt.Errorf("postgres api key store: Prefix %q must match %s", options.Prefix, prefixPattern)
	case options.LastUsedInterval < 0:
		return nil, fmt.Errorf("postgres api key store: LastUsedInterval %s is negative", options.LastUsedInterval)
	}
	interval := options.LastUsedInterval
	if interval == 0 {
		interval = defaultLastUsedInterval
	}
	return &Store{pool: options.Pool, prefix: options.Prefix, load: options.Load, lastUsedInterval: interval, now: time.Now}, nil
}

// Issue creates a key for ownerID and returns its text, which is never available again, and the stored key.
// An invalid request is an *auth.Error of kind auth.ErrInvalidRequest naming the problem in its Reason.
func (s *Store) Issue(ctx context.Context, ownerID uuid.UUID, request IssueRequest) (string, *Key, error) {
	now := s.now().Truncate(time.Microsecond) // PostgreSQL's precision, so List returns the same CreatedAt
	if err := validate(request, now); err != nil {
		return "", nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", nil, fmt.Errorf("postgres api key store: new key ID: %w", err)
	}
	secret, err := random.Token(secretBytes)
	if err != nil {
		return "", nil, fmt.Errorf("postgres api key store: new key secret: %w", err)
	}
	hash := sha256.Sum256([]byte(secret))
	_, err = s.pool.Exec(ctx, insertKey, id, ownerID, request.Name, hash[:], scopeTexts(request.Scopes), now, nullableTime(request.ExpiresAt))
	if err != nil {
		return "", nil, dependency.Error("postgres api key store: issue key", err)
	}
	key := &Key{ID: id, OwnerID: ownerID, Name: request.Name, Scopes: slices.Clone(request.Scopes), CreatedAt: now, ExpiresAt: request.ExpiresAt}
	return s.prefix + "_" + hex.EncodeToString(id[:]) + "." + secret, key, nil
}

// List returns the keys of ownerID, oldest first, expired ones included.
func (s *Store) List(ctx context.Context, ownerID uuid.UUID) ([]Key, error) {
	rows, err := s.pool.Query(ctx, selectKeys, ownerID)
	if err != nil {
		return nil, dependency.Error("postgres api key store: list keys", err)
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Key, error) {
		var key Key
		var scopes []string
		var expiresAt, lastUsedAt *time.Time
		if err := row.Scan(&key.ID, &key.OwnerID, &key.Name, &scopes, &key.CreatedAt, &expiresAt, &lastUsedAt); err != nil {
			return Key{}, err
		}
		key.ExpiresAt, key.LastUsedAt = valueOf(expiresAt), valueOf(lastUsedAt)
		key.Scopes, err = parseScopes(scopes)
		return key, err
	})
	if err != nil {
		return nil, dependency.Error("postgres api key store: list keys", err)
	}
	return keys, nil
}

// Revoke deletes the key id of ownerID; ErrKeyNotFound when ownerID has no such key. The next request
// presenting it is refused.
func (s *Store) Revoke(ctx context.Context, ownerID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, deleteKey, ownerID, id)
	if err != nil {
		return dependency.Error("postgres api key store: revoke key", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrKeyNotFound
	}
	return nil
}

// Resolve is the apikey.Resolver of the store: it returns the identity of a presented key (see Store), or an
// error matching auth.ErrUnauthenticated for a key that is malformed, unknown, wrong, expired or whose owner
// Load refuses. A key of the wrong shape is refused before any query. Errors never contain the key.
func (s *Store) Resolve(ctx context.Context, key string) (*auth.Identity, error) {
	id, secret, ok := s.parse(key)
	if !ok {
		return nil, refused("malformed key")
	}
	var ownerID uuid.UUID
	var hash []byte
	var scopes []string
	var expiresAt, lastUsedAt *time.Time
	err := s.pool.QueryRow(ctx, selectKeyForResolve, id).Scan(&ownerID, &hash, &scopes, &expiresAt, &lastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refused("unknown key")
	}
	if err != nil {
		return nil, dependency.Error("postgres api key store: read key", err)
	}
	presented := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(presented[:], hash) != 1 {
		return nil, refused("wrong secret")
	}
	now := s.now()
	if expiresAt != nil && !expiresAt.After(now) {
		return nil, refused("expired key")
	}
	permissions, err := parseScopes(scopes)
	if err != nil {
		return nil, fmt.Errorf("postgres api key store: stored scopes: %w", err)
	}
	owner, err := s.loadOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	if err := s.touch(ctx, id, valueOf(lastUsedAt), now); err != nil {
		return nil, err
	}
	return restrict(owner, ownerID, id, permissions), nil
}

var _ apikey.Resolver = (*Store)(nil).Resolve

func (s *Store) loadOwner(ctx context.Context, ownerID uuid.UUID) (*auth.Identity, error) {
	owner, err := s.load(ctx, ownerID)
	if errors.Is(err, auth.ErrUnauthenticated) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("postgres api key store: load owner: %w", err)
	}
	if owner == nil {
		return nil, refused("no owner identity")
	}
	return owner, nil
}

// touch writes the use time when the stored one is older than the interval.
func (s *Store) touch(ctx context.Context, id uuid.UUID, lastUsedAt, now time.Time) error {
	staleBefore := now.Add(-s.lastUsedInterval)
	if lastUsedAt.After(staleBefore) {
		return nil
	}
	if _, err := s.pool.Exec(ctx, touchKey, id, now, staleBefore); err != nil {
		return dependency.Error("postgres api key store: record key use", err)
	}
	return nil
}

// parse checks the shape "<prefix>_<32 lower-case hex>.<43 base64url>" and returns the ID and the secret.
func (s *Store) parse(key string) (uuid.UUID, string, bool) {
	rest, found := strings.CutPrefix(key, s.prefix+"_")
	if !found {
		return uuid.Nil, "", false
	}
	idText, secret, found := strings.Cut(rest, ".")
	if !found || len(idText) != idLength || len(secret) != secretLength ||
		strings.Trim(idText, "0123456789abcdef") != "" ||
		strings.Trim(secret, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return uuid.Nil, "", false
	}
	id, err := uuid.Parse(idText)
	if err != nil {
		return uuid.Nil, "", false
	}
	return id, secret, true
}

func validate(request IssueRequest, now time.Time) error {
	switch {
	case strings.TrimSpace(request.Name) == "":
		return invalid("name is required")
	case len(request.Name) > maximumNameBytes:
		return invalid(fmt.Sprintf("name is longer than %d bytes", maximumNameBytes))
	case len(request.Scopes) == 0:
		return invalid("at least one scope is required")
	case !request.ExpiresAt.IsZero() && !request.ExpiresAt.After(now):
		return invalid("expiry is not in the future")
	}
	for _, scope := range request.Scopes {
		if err := scope.Validate(); err != nil {
			return invalid(err.Error())
		}
	}
	return nil
}

// restrict returns the identity a key acts as: the owner's, narrowed to the key's scopes (see Store).
func restrict(owner *auth.Identity, ownerID, keyID uuid.UUID, scopes []auth.Permission) *auth.Identity {
	identity := owner.Clone()
	identity.Provider = auth.ProviderAPIKey
	identity.Subject = keyID.String()
	identity.Impersonator = nil
	if identity.UserID == uuid.Nil {
		identity.UserID = ownerID
	}
	identity.Permissions = intersect(owner.Permissions, scopes)
	if !slices.Contains(scopes, fullAccess) {
		identity.Roles, identity.OIDCRoles, identity.OIDCClientRoles, identity.Groups, identity.Teams = nil, nil, nil, nil, nil
	}
	return identity
}

// intersect returns the permissions that grant exactly what both a permission of granted and one of scopes
// grant: for every pair the narrower resource and the lower access.
func intersect(granted, scopes []auth.Permission) []auth.Permission {
	var result []auth.Permission
	for _, permission := range granted {
		if permission.Validate() != nil {
			continue
		}
		for _, scope := range scopes {
			narrowed, ok := narrow(permission, scope)
			if ok && !slices.Contains(result, narrowed) {
				result = append(result, narrowed)
			}
		}
	}
	return result
}

func narrow(first, second auth.Permission) (auth.Permission, bool) {
	resource := first.Resource
	switch {
	case first.Resource == auth.AllResources:
		resource = second.Resource
	case second.Resource != auth.AllResources && second.Resource != first.Resource:
		return auth.Permission{}, false
	}
	access := auth.AccessWrite
	if first.Access == auth.AccessRead || second.Access == auth.AccessRead {
		access = auth.AccessRead
	}
	return auth.Permission{Resource: resource, Access: access}, true
}

func scopeTexts(scopes []auth.Permission) []string {
	texts := make([]string, len(scopes))
	for index, scope := range scopes {
		texts[index] = scope.String()
	}
	return texts
}

func parseScopes(texts []string) ([]auth.Permission, error) {
	scopes := make([]auth.Permission, len(texts))
	for index, text := range texts {
		scope, err := auth.ParsePermission(text)
		if err != nil {
			return nil, err
		}
		scopes[index] = scope
	}
	return scopes, nil
}

func refused(reason string) error {
	return &auth.Error{Kind: auth.ErrUnauthenticated, Reason: reason}
}

func invalid(reason string) error {
	return &auth.Error{Kind: auth.ErrInvalidRequest, Reason: reason}
}

func nullableTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func valueOf(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}
