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
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/internal/random"
)

const (
	defaultLastUsedInterval = time.Minute
	secretBytes             = 32
	secretLength            = 43 // base64url without padding of secretBytes
	idLength                = 32 // the key ID as lower-case hex without dashes
	maximumNameBytes        = 200
	maximumPageSize         = 1000
	// foreignKeyViolation is the SQLSTATE of an insert whose owner the application's foreign key misses.
	foreignKeyViolation = "23503"
)

// prefixPattern keeps the prefix recognizable for secret scanners and free of the separators "_" and ".".
var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)

// fullAccess is the scope that leaves the owner's identity whole, roles included.
var fullAccess = auth.Permission{Resource: auth.AllResources, Access: auth.AccessWrite}

// ErrKeyNotFound is returned by Get, Revoke and RevokeAny when no key has the ID (for Revoke: none of the owner).
var ErrKeyNotFound = errors.New("api key not found")

// ErrOwnerNotFound is returned by Issue when the application's foreign key on owner_id refuses the owner
// (SQLSTATE 23503). The PostgreSQL error stays in the chain. Inside a transaction the transaction is
// aborted then: roll it back.
var ErrOwnerNotFound = errors.New("api key owner not found")

// keyColumns are the columns of a Key, in the order scanKey reads them.
const keyColumns = `id, owner_id, name, scopes, created_at, expires_at, last_used_at, revoked_at`

const insertKey = `
INSERT INTO govengers_auth_api_keys (id, owner_id, name, secret_hash, scopes, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

const selectOwnerKeys = `SELECT ` + keyColumns + ` FROM govengers_auth_api_keys WHERE owner_id = $1 ORDER BY created_at, id`

const selectKey = `SELECT ` + keyColumns + ` FROM govengers_auth_api_keys WHERE id = $1`

// selectKeyPage pages through every owner's keys in ID order (UUIDv7, so about issue order), after $1.
const selectKeyPage = `SELECT ` + keyColumns + ` FROM govengers_auth_api_keys WHERE id > $1 ORDER BY id LIMIT $2`

// revokeKey marks a key revoked, of the owner $2 or (NULL) of any owner. A key revoked before keeps its
// first revocation time.
const revokeKey = `
UPDATE govengers_auth_api_keys SET revoked_at = COALESCE(revoked_at, $3)
WHERE id = $1 AND ($2::uuid IS NULL OR owner_id = $2)
RETURNING ` + keyColumns

// purgeKeys deletes the keys that ended (revoked, or expired) before $1; LEAST ignores a NULL.
const purgeKeys = `DELETE FROM govengers_auth_api_keys WHERE LEAST(revoked_at, expires_at) < $1`

const selectKeyForResolve = `
SELECT owner_id, secret_hash, scopes, expires_at, last_used_at, revoked_at FROM govengers_auth_api_keys WHERE id = $1`

// touchKey records a use at most once per interval: of concurrent requests only the first writes.
const touchKey = `
UPDATE govengers_auth_api_keys SET last_used_at = $2
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at <= $3)`

// Executor runs the store's statements: a *pgxpool.Pool, a *pgx.Conn, a pgx.Tx, or the query handle of a
// govengers/livewire unit of work (postgresadapter.TransactionFrom). See Store.WithExecutor.
type Executor interface {
	Exec(ctx context.Context, statement string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, statement string, arguments ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, statement string, arguments ...any) pgx.Row
}

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
	RevokedAt  time.Time // zero: not revoked; a revoked key is refused and stays listed until Purge
}

// IssueRequest describes a key to issue.
type IssueRequest struct {
	Name      string            // required, at most 200 bytes, for the owner's list
	Scopes    []auth.Permission // required, each valid; they cap the owner's permissions (see Store)
	ExpiresAt time.Time         // zero: never expires; otherwise in the future
}

// Store issues, lists and revokes per-owner API keys in PostgreSQL and resolves presented keys for an
// apikey.Authenticator. Its statements run on Options.Pool, or on the caller's transaction through
// WithExecutor. A key is "<Prefix>_<id>.<secret>": id is the key's UUID in hex, secret 32 random
// bytes in base64url; the table holds the SHA-256 of the secret only. It is safe for concurrent use.
//
// A resolved key acts as its owner (Load) narrowed to its scopes: the identity's Permissions become those
// both the owner's permissions and the key's scopes grant, and a key without the scope "*:write" also drops
// the owner's Roles, OIDCRoles, OIDCClientRoles, Groups and Teams, which no resource scope can narrow.
// Provider is "apikey", Subject the key ID, UserID the owner's (Load's, else the owner ID), and the
// identity never impersonates.
//
// Scopes bind permission checks only: UserID, Active, Attributes, Claims and Data stay the owner's, so a key
// with the single scope "tasks:read" still passes IsAuthenticated, IsUser and HasUserID(owner). Guard every
// route a key may reach with HasPermission, also routes an ownership check alone would cover (change my
// profile, delete my account), or keep keys off them.
//
// A revoked key stays a row, so the key ID an audit entry names as actor still leads to its owner (Get);
// Purge deletes ended keys after a retention. Issue, List and Revoke act for one owner; Get, ListAll and
// RevokeAny reach every owner's keys for an administrator's view. The store checks no caller: the
// application authorizes every call.
type Store struct {
	pool             *pgxpool.Pool
	database         Executor // the pool, or the executor of a WithExecutor view
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
	return &Store{pool: options.Pool, database: options.Pool, prefix: options.Prefix, load: options.Load, lastUsedInterval: interval, now: time.Now}, nil
}

// WithExecutor returns a view of the store whose every statement, reads included, runs on executor, usually
// the caller's transaction: a key is issued or revoked in the same commit as the application's own rows and
// audit entry, and a call inside a transaction never waits for a second connection of the pool. A nil
// executor is the pool (so `store.WithExecutor(postgresadapter.TransactionFrom(ctx))` works outside a unit
// of work too). The view shares the store's options; the store itself keeps using the pool.
//
// On a transaction the statements see its uncommitted rows (an owner inserted before Issue) and its
// isolation: Revoke and the last-use write of Resolve need a read-write transaction, and under REPEATABLE
// READ a concurrent change of the same key fails with a serialization error instead of waiting. An error
// returned from the database aborts the transaction; ErrKeyNotFound and the refusals of Resolve and Issue
// that need no statement leave it usable.
func (s *Store) WithExecutor(executor Executor) *Store {
	view := *s
	view.database = executor
	if executor == nil {
		view.database = s.pool
	}
	return &view
}

// Issue creates a key for ownerID and returns its text, which is never available again, and the stored key.
// An invalid request is an *auth.Error of kind auth.ErrInvalidRequest naming the problem in its Reason; an
// owner the application's foreign key refuses is ErrOwnerNotFound.
func (s *Store) Issue(ctx context.Context, ownerID uuid.UUID, request IssueRequest) (string, *Key, error) {
	now := s.now().Truncate(time.Microsecond) // PostgreSQL's precision, so List returns the same times
	request.ExpiresAt = request.ExpiresAt.Truncate(time.Microsecond)
	if ownerID == uuid.Nil {
		return "", nil, invalid("owner ID is nil")
	}
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
	_, err = s.database.Exec(ctx, insertKey, id, ownerID, request.Name, hash[:], scopeTexts(request.Scopes), now, nullableTime(request.ExpiresAt))
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == foreignKeyViolation {
		return "", nil, fmt.Errorf("postgres api key store: issue key: %w: %w", ErrOwnerNotFound, err)
	}
	if err != nil {
		return "", nil, fmt.Errorf("postgres api key store: issue key: %w", err)
	}
	key := &Key{ID: id, OwnerID: ownerID, Name: request.Name, Scopes: slices.Clone(request.Scopes), CreatedAt: now, ExpiresAt: request.ExpiresAt}
	return s.prefix + "_" + hex.EncodeToString(id[:]) + "." + secret, key, nil
}

// List returns the keys of ownerID, oldest first, expired and revoked ones included.
func (s *Store) List(ctx context.Context, ownerID uuid.UUID) ([]Key, error) {
	return s.query(ctx, "list keys", selectOwnerKeys, ownerID)
}

// ListAll returns up to limit keys of every owner in ID order (about issue order), starting after the key
// ID after; uuid.Nil starts at the first key. Pass the last ID of a page for the next one; a page shorter
// than limit is the last. A limit outside 1 to 1000 is an *auth.Error of kind auth.ErrInvalidRequest.
func (s *Store) ListAll(ctx context.Context, after uuid.UUID, limit int) ([]Key, error) {
	if limit < 1 || limit > maximumPageSize {
		return nil, invalid(fmt.Sprintf("limit %d is outside 1 to %d", limit, maximumPageSize))
	}
	return s.query(ctx, "list all keys", selectKeyPage, after, limit)
}

// Get returns the key id of any owner, revoked or expired included, or ErrKeyNotFound: the owner of the key
// an audit entry names.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (*Key, error) {
	return s.queryOne(ctx, "get key", selectKey, id)
}

// Revoke marks the key id of ownerID revoked and returns it; ErrKeyNotFound when ownerID has no such key.
// The next request presenting it is refused on every replica. The row stays (see Purge); revoking a revoked
// key keeps its first revocation time.
func (s *Store) Revoke(ctx context.Context, ownerID, id uuid.UUID) (*Key, error) {
	return s.queryOne(ctx, "revoke key", revokeKey, id, ownerID, s.now().Truncate(time.Microsecond))
}

// RevokeAny is Revoke for the key id of any owner, for an administrator; ErrKeyNotFound when no key has id.
func (s *Store) RevokeAny(ctx context.Context, id uuid.UUID) (*Key, error) {
	return s.queryOne(ctx, "revoke key", revokeKey, id, nil, s.now().Truncate(time.Microsecond))
}

// Purge deletes the keys that were revoked, or expired, longer than retention ago and returns how many. Audit
// entries naming a purged key no longer lead to its owner, so keep retention at least as long as the audit
// log's. A negative retention is an *auth.Error of kind auth.ErrInvalidRequest.
func (s *Store) Purge(ctx context.Context, retention time.Duration) (int64, error) {
	if retention < 0 {
		return 0, invalid(fmt.Sprintf("retention %s is negative", retention))
	}
	tag, err := s.database.Exec(ctx, purgeKeys, s.now().Add(-retention))
	if err != nil {
		return 0, fmt.Errorf("postgres api key store: purge keys: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) query(ctx context.Context, operation, statement string, arguments ...any) ([]Key, error) {
	rows, err := s.database.Query(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres api key store: %s: %w", operation, err)
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Key, error) { return scanKey(row) })
	if err != nil {
		return nil, fmt.Errorf("postgres api key store: %s: %w", operation, err)
	}
	return keys, nil
}

func (s *Store) queryOne(ctx context.Context, operation, statement string, arguments ...any) (*Key, error) {
	key, err := scanKey(s.database.QueryRow(ctx, statement, arguments...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres api key store: %s: %w", operation, err)
	}
	return &key, nil
}

// scanKey reads the keyColumns of a row.
func scanKey(row pgx.Row) (Key, error) {
	var key Key
	var scopes []string
	var expiresAt, lastUsedAt, revokedAt *time.Time
	if err := row.Scan(&key.ID, &key.OwnerID, &key.Name, &scopes, &key.CreatedAt, &expiresAt, &lastUsedAt, &revokedAt); err != nil {
		return Key{}, err
	}
	key.ExpiresAt, key.LastUsedAt, key.RevokedAt = valueOf(expiresAt), valueOf(lastUsedAt), valueOf(revokedAt)
	var err error
	if key.Scopes, err = parseScopes(scopes); err != nil {
		return Key{}, fmt.Errorf("stored scopes: %w", err)
	}
	return key, nil
}

// Resolve is the apikey.Resolver of the store: it returns the identity of a presented key (see Store), or an
// error matching auth.ErrUnauthenticated for a key that is malformed, unknown, wrong, expired, revoked or
// whose owner Load refuses. A key of the wrong shape is refused before any query. Errors never contain the key.
//
// Recording the use is part of the check: when the last-use write is due (LastUsedInterval) and fails, a
// read-only database during a failover for instance, Resolve returns that error and the request is refused
// although the key is valid. Keys therefore need a writable database, like logins do.
func (s *Store) Resolve(ctx context.Context, key string) (*auth.Identity, error) {
	id, secret, ok := s.parse(key)
	if !ok {
		return nil, refused("malformed key")
	}
	var ownerID uuid.UUID
	var hash []byte
	var scopes []string
	var expiresAt, lastUsedAt, revokedAt *time.Time
	err := s.database.QueryRow(ctx, selectKeyForResolve, id).Scan(&ownerID, &hash, &scopes, &expiresAt, &lastUsedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refused("unknown key")
	}
	if err != nil {
		return nil, fmt.Errorf("postgres api key store: read key: %w", err)
	}
	presented := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(presented[:], hash) != 1 {
		return nil, refused("wrong secret")
	}
	if revokedAt != nil {
		return nil, refused("revoked key")
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
	if _, err := s.database.Exec(ctx, touchKey, id, now, staleBefore); err != nil {
		return fmt.Errorf("postgres api key store: record key use: %w", err)
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
	case !utf8.ValidString(request.Name) || strings.ContainsRune(request.Name, 0):
		return invalid("name is not valid UTF-8 or contains a NUL byte") // PostgreSQL text holds neither
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
