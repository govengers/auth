package postgresstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/govengers/postgrestest"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/apikey/postgresstore"
)

// postgres gives every test a database of its own with the migrations applied.
var postgres = postgrestest.New(&postgrestest.Options{
	Migrate:     postgrestest.Statements(postgresstore.MigrationV1, postgresstore.MigrationV2),
	Fingerprint: postgresstore.MigrationV1 + postgresstore.MigrationV2,
})

func TestMain(m *testing.M) { goleak.VerifyTestMain(postgres.Main(m)) }

var (
	tasksRead  = auth.Permission{Resource: "tasks", Access: auth.AccessRead}
	tasksWrite = auth.Permission{Resource: "tasks", Access: auth.AccessWrite}
	allRead    = auth.Permission{Resource: auth.AllResources, Access: auth.AccessRead}
	allWrite   = auth.Permission{Resource: auth.AllResources, Access: auth.AccessWrite}
)

var start = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

type fixture struct {
	store  *postgresstore.Store
	pool   *pgxpool.Pool
	now    time.Time
	owner  uuid.UUID
	owners map[uuid.UUID]*auth.Identity // what Load returns; a missing owner is unauthenticated
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := postgres.Pool(t)
	fixture := &fixture{pool: pool, now: start, owner: uuid.New()}
	fixture.owners = map[uuid.UUID]*auth.Identity{fixture.owner: {
		Provider:    "password",
		Subject:     fixture.owner.String(),
		Username:    "ada",
		Active:      true,
		Roles:       []string{auth.RoleAdmin},
		Groups:      []string{"staff"},
		Permissions: []auth.Permission{allWrite},
	}}
	store, err := postgresstore.New(&postgresstore.Options{Pool: pool, Prefix: "todo", Load: fixture.load})
	require.NoError(t, err)
	postgresstore.SetClock(store, func() time.Time { return fixture.now })
	fixture.store = store
	return fixture
}

func (f *fixture) load(_ context.Context, _ postgresstore.Executor, ownerID uuid.UUID) (*auth.Identity, error) {
	identity, found := f.owners[ownerID]
	if !found {
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "owner deleted"}
	}
	return identity, nil
}

func (f *fixture) issue(t *testing.T, scopes ...auth.Permission) (string, *postgresstore.Key) {
	t.Helper()
	text, key, err := f.store.Issue(t.Context(), f.owner, postgresstore.IssueRequest{Name: "ci", Scopes: scopes})
	require.NoError(t, err)
	return text, key
}

func TestNew(t *testing.T) {
	pool := postgres.Pool(t)
	load := func(context.Context, postgresstore.Executor, uuid.UUID) (*auth.Identity, error) { return nil, nil }
	testCases := []struct {
		name      string
		options   *postgresstore.Options
		wantError string
	}{
		{name: "nil options", wantError: "Pool is required"},
		{name: "no pool", options: &postgresstore.Options{Prefix: "todo", Load: load}, wantError: "Pool is required"},
		{name: "no loader", options: &postgresstore.Options{Pool: pool, Prefix: "todo"}, wantError: "Load is required"},
		{name: "no prefix", options: &postgresstore.Options{Pool: pool, Load: load}, wantError: "Prefix"},
		{name: "prefix with underscore", options: &postgresstore.Options{Pool: pool, Prefix: "to_do", Load: load}, wantError: "Prefix"},
		{name: "upper-case prefix", options: &postgresstore.Options{Pool: pool, Prefix: "Todo", Load: load}, wantError: "Prefix"},
		{name: "negative interval", options: &postgresstore.Options{Pool: pool, Prefix: "todo", Load: load, LastUsedInterval: -time.Second}, wantError: "negative"},
		{name: "valid", options: &postgresstore.Options{Pool: pool, Prefix: "todo", Load: load}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := postgresstore.New(testCase.options)
			if testCase.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, testCase.wantError)
		})
	}
}

func TestIssueReturnsTheKeyOnceAndStoresOnlyItsHash(t *testing.T) {
	fixture := newFixture(t)

	text, key, err := fixture.store.Issue(t.Context(), fixture.owner, postgresstore.IssueRequest{
		Name: "ci", Scopes: []auth.Permission{tasksRead}, ExpiresAt: start.Add(time.Hour + time.Nanosecond), // below PostgreSQL's precision
	})

	require.NoError(t, err)
	require.Regexp(t, `^todo_[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$`, text)
	require.Equal(t, strings.ReplaceAll(key.ID.String(), "-", ""), text[5:37])
	require.Equal(t, postgresstore.Key{ID: key.ID, OwnerID: fixture.owner, Name: "ci", Scopes: []auth.Permission{tasksRead}, CreatedAt: start, ExpiresAt: start.Add(time.Hour)}, *key)
	var storedHash []byte
	var rowsWithTheSecret int
	require.NoError(t, fixture.pool.QueryRow(t.Context(), `SELECT secret_hash FROM govengers_auth_api_keys`).Scan(&storedHash))
	require.NoError(t, fixture.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM govengers_auth_api_keys AS stored WHERE stored::text LIKE '%' || $1 || '%'`, text[38:]).Scan(&rowsWithTheSecret))
	secretHash := sha256.Sum256([]byte(text[38:]))
	require.Equal(t, secretHash[:], storedHash)
	require.Zero(t, rowsWithTheSecret, "the secret is not stored")
	listed, err := fixture.store.List(t.Context(), fixture.owner)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.Equal(t, key.ID, listed[0].ID)
	require.True(t, key.CreatedAt.Equal(listed[0].CreatedAt))
	require.True(t, key.ExpiresAt.Equal(listed[0].ExpiresAt))
	require.Equal(t, key.Scopes, listed[0].Scopes)
	require.True(t, listed[0].LastUsedAt.IsZero())
}

func TestIssueRefusesInvalidRequests(t *testing.T) {
	fixture := newFixture(t)
	testCases := []struct {
		name    string
		request postgresstore.IssueRequest
		reason  string
	}{
		{name: "no name", request: postgresstore.IssueRequest{Name: " ", Scopes: []auth.Permission{tasksRead}}, reason: "name is required"},
		{name: "long name", request: postgresstore.IssueRequest{Name: strings.Repeat("x", 201), Scopes: []auth.Permission{tasksRead}}, reason: "longer than 200"},
		{name: "NUL byte in name", request: postgresstore.IssueRequest{Name: "a\x00b", Scopes: []auth.Permission{tasksRead}}, reason: "NUL byte"},
		{name: "invalid UTF-8 name", request: postgresstore.IssueRequest{Name: "caf\xff", Scopes: []auth.Permission{tasksRead}}, reason: "not valid UTF-8"},
		{name: "no scope", request: postgresstore.IssueRequest{Name: "ci"}, reason: "at least one scope"},
		{name: "invalid scope", request: postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{{Resource: "Tasks", Access: auth.AccessRead}}}, reason: "resource must be"},
		{name: "past expiry", request: postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{tasksRead}, ExpiresAt: start}, reason: "not in the future"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, err := fixture.store.Issue(t.Context(), fixture.owner, testCase.request)
			require.ErrorIs(t, err, auth.ErrInvalidRequest)
			require.ErrorContains(t, err, testCase.reason)
		})
	}
	_, _, err := fixture.store.Issue(t.Context(), uuid.Nil, postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{tasksRead}})
	require.ErrorIs(t, err, auth.ErrInvalidRequest)
	require.ErrorContains(t, err, "owner ID is nil")
}

func TestResolveNarrowsTheOwnerToTheKeysScopes(t *testing.T) {
	fixture := newFixture(t)
	narrowText, narrowKey := fixture.issue(t, tasksRead)
	fullText, fullKey := fixture.issue(t, allWrite)

	narrow, err := fixture.store.Resolve(t.Context(), narrowText)
	require.NoError(t, err)
	require.Equal(t, &auth.Identity{
		Provider:    auth.ProviderAPIKey,
		Subject:     narrowKey.ID.String(),
		UserID:      fixture.owner,
		Username:    "ada",
		Active:      true,
		Permissions: []auth.Permission{tasksRead},
	}, narrow, "a narrowed key drops roles and groups")

	full, err := fixture.store.Resolve(t.Context(), fullText)
	require.NoError(t, err)
	require.Equal(t, fullKey.ID.String(), full.Subject)
	require.Equal(t, []string{auth.RoleAdmin}, full.Roles, "a *:write key keeps the owner's roles")
	require.Equal(t, []string{"staff"}, full.Groups)
	require.Equal(t, []auth.Permission{allWrite}, full.Permissions)

	fixture.owners[fixture.owner].Permissions = []auth.Permission{tasksRead}
	full, err = fixture.store.Resolve(t.Context(), fullText)
	require.NoError(t, err)
	require.Equal(t, []auth.Permission{tasksRead}, full.Permissions, "a key never grants more than its owner has")
}

func TestResolveDropsAnImpersonatorAndKeepsLoadsUserID(t *testing.T) {
	fixture := newFixture(t)
	applicationUserID := uuid.New()
	fixture.owners[fixture.owner].UserID = applicationUserID
	fixture.owners[fixture.owner].Impersonator = &auth.Identity{Subject: "admin", Active: true}
	text, _ := fixture.issue(t, allWrite)

	identity, err := fixture.store.Resolve(t.Context(), text)

	require.NoError(t, err)
	require.Nil(t, identity.Impersonator)
	require.Equal(t, applicationUserID, identity.UserID)
	require.NotNil(t, fixture.owners[fixture.owner].Impersonator, "the loaded identity is not modified")
}

func TestResolveRefusals(t *testing.T) {
	fixture := newFixture(t)
	text, key := fixture.issue(t, tasksRead)
	expiring, _, err := fixture.store.Issue(t.Context(), fixture.owner, postgresstore.IssueRequest{Name: "short", Scopes: []auth.Permission{tasksRead}, ExpiresAt: start.Add(time.Minute)})
	require.NoError(t, err)
	revoked, revokedKey := fixture.issue(t, tasksRead)
	_, _, err = fixture.store.Revoke(t.Context(), fixture.owner, revokedKey.ID)
	require.NoError(t, err)
	fixture.now = start.Add(time.Minute)
	other := uuid.New()
	orphaned, _, err := fixture.store.Issue(t.Context(), other, postgresstore.IssueRequest{Name: "orphan", Scopes: []auth.Permission{tasksRead}})
	require.NoError(t, err)
	secret := text[38:]
	testCases := []struct {
		name   string
		key    string
		reason string
	}{
		{name: "other prefix", key: "other_" + text[5:], reason: "malformed key"},
		{name: "no separator", key: strings.Replace(text, ".", "", 1), reason: "malformed key"},
		{name: "upper-case ID", key: "todo_" + strings.ToUpper(text[5:37]) + "." + secret, reason: "malformed key"},
		{name: "short secret", key: text[:len(text)-1], reason: "malformed key"},
		{name: "secret outside base64url", key: text[:len(text)-1] + "=", reason: "malformed key"},
		{name: "unknown ID", key: "todo_" + strings.ReplaceAll(uuid.New().String(), "-", "") + "." + secret, reason: "unknown key"},
		{name: "wrong secret", key: text[:38] + strings.Repeat("A", 43), reason: "wrong secret"},
		{name: "expired", key: expiring, reason: "expired key"},
		{name: "revoked", key: revoked, reason: "revoked key"},
		{name: "revoked with a wrong secret", key: revoked[:38] + strings.Repeat("A", 43), reason: "wrong secret"},
		{name: "owner gone", key: orphaned, reason: "owner deleted"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			identity, err := fixture.store.Resolve(t.Context(), testCase.key)
			require.Nil(t, identity)
			require.ErrorIs(t, err, auth.ErrUnauthenticated)
			require.ErrorContains(t, err, testCase.reason)
			require.NotContains(t, err.Error(), secret)
		})
	}
	_, err = fixture.store.Resolve(t.Context(), text)
	require.NoError(t, err, "key %s still works", key.ID)
}

func TestResolveReportsLoadFailures(t *testing.T) {
	pool := postgres.Pool(t)
	owner := uuid.New()
	var loadError error
	var loaded *auth.Identity
	store, err := postgresstore.New(&postgresstore.Options{Pool: pool, Prefix: "todo", Load: func(context.Context, postgresstore.Executor, uuid.UUID) (*auth.Identity, error) {
		return loaded, loadError
	}})
	require.NoError(t, err)
	text, _, err := store.Issue(t.Context(), owner, postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{tasksRead}})
	require.NoError(t, err)

	loadError = errors.New("users table unreachable")
	_, err = store.Resolve(t.Context(), text)
	require.ErrorContains(t, err, "load owner: users table unreachable")
	require.NotErrorIs(t, err, auth.ErrUnauthenticated)

	loadError = nil
	_, err = store.Resolve(t.Context(), text)
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "no identity")
}

func TestLastUsedIsWrittenOncePerInterval(t *testing.T) {
	fixture := newFixture(t)
	text, _ := fixture.issue(t, tasksRead)
	lastUsed := func() time.Time {
		keys, err := fixture.store.List(t.Context(), fixture.owner)
		require.NoError(t, err)
		return keys[0].LastUsedAt
	}
	resolve := func() {
		_, err := fixture.store.Resolve(t.Context(), text)
		require.NoError(t, err)
	}

	resolve()
	require.True(t, start.Equal(lastUsed()))
	fixture.now = start.Add(59 * time.Second)
	resolve()
	require.True(t, start.Equal(lastUsed()), "within the interval nothing is written")
	fixture.now = start.Add(time.Minute)
	resolve()
	require.True(t, start.Add(time.Minute).Equal(lastUsed()))
}

func TestListAndRevokeArePerOwner(t *testing.T) {
	fixture := newFixture(t)
	_, first := fixture.issue(t, tasksRead)
	fixture.now = start.Add(time.Second)
	_, second := fixture.issue(t, tasksWrite)
	other := uuid.New()

	keys, err := fixture.store.List(t.Context(), fixture.owner)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{first.ID, second.ID}, []uuid.UUID{keys[0].ID, keys[1].ID})
	otherKeys, err := fixture.store.List(t.Context(), other)
	require.NoError(t, err)
	require.Empty(t, otherKeys)

	_, _, err = fixture.store.Revoke(t.Context(), other, first.ID)
	require.ErrorIs(t, err, postgresstore.ErrKeyNotFound, "another owner's key")
	_, _, err = fixture.store.Revoke(t.Context(), fixture.owner, uuid.New())
	require.ErrorIs(t, err, postgresstore.ErrKeyNotFound)
	fixture.now = start.Add(time.Minute + time.Nanosecond)
	revoked, revokedNow, err := fixture.store.Revoke(t.Context(), fixture.owner, first.ID)
	require.NoError(t, err)
	require.True(t, revokedNow, "this call revoked it")
	require.Equal(t, first.ID, revoked.ID)
	require.Equal(t, fixture.owner, revoked.OwnerID)
	require.True(t, start.Add(time.Minute).Equal(revoked.RevokedAt), "truncated to PostgreSQL's precision")
	fixture.now = start.Add(time.Hour)
	again, revokedAgain, err := fixture.store.Revoke(t.Context(), fixture.owner, first.ID)
	require.NoError(t, err, "revoking a revoked key changes nothing")
	require.False(t, revokedAgain, "revoked before, so no second audit entry")
	require.Equal(t, first.ID, again.ID)
	require.True(t, revoked.RevokedAt.Equal(again.RevokedAt), "the first revocation time stays")
	_, _, err = fixture.store.Revoke(t.Context(), other, first.ID)
	require.ErrorIs(t, err, postgresstore.ErrKeyNotFound, "another owner's revoked key")

	keys, err = fixture.store.List(t.Context(), fixture.owner)
	require.NoError(t, err)
	require.Len(t, keys, 2, "a revoked key stays listed")
	require.True(t, revoked.RevokedAt.Equal(keys[0].RevokedAt))
	require.True(t, keys[1].RevokedAt.IsZero())
}

// Audit entries name a key ID as actor: Get leads from it to the owner, also after the key was revoked, until
// Purge deletes it after the retention.
func TestRevokedAndExpiredKeysStayUntilPurged(t *testing.T) {
	fixture := newFixture(t)
	_, active := fixture.issue(t, tasksRead)
	_, revokedEarly := fixture.issue(t, tasksRead)
	_, revokedLate := fixture.issue(t, tasksRead)
	issueExpiring := func(expiresAt time.Time) *postgresstore.Key {
		t.Helper()
		_, key, err := fixture.store.Issue(t.Context(), fixture.owner, postgresstore.IssueRequest{Name: "expiring", Scopes: []auth.Permission{tasksRead}, ExpiresAt: expiresAt})
		require.NoError(t, err)
		return key
	}
	expiring := issueExpiring(start.Add(time.Hour))
	revokedBeforeExpiry := issueExpiring(start.Add(365 * 24 * time.Hour))
	expiredBeforeRevoked := issueExpiring(start.Add(time.Hour))
	for _, key := range []*postgresstore.Key{revokedEarly, revokedBeforeExpiry} {
		_, _, err := fixture.store.Revoke(t.Context(), fixture.owner, key.ID)
		require.NoError(t, err)
	}
	fixture.now = start.Add(48 * time.Hour)
	for _, key := range []*postgresstore.Key{revokedLate, expiredBeforeRevoked} {
		_, _, err := fixture.store.Revoke(t.Context(), fixture.owner, key.ID)
		require.NoError(t, err)
	}

	got, err := fixture.store.Get(t.Context(), revokedEarly.ID)
	require.NoError(t, err)
	require.Equal(t, fixture.owner, got.OwnerID, "a revoked key still names its owner")
	require.True(t, start.Equal(got.RevokedAt))

	_, err = fixture.store.Purge(t.Context(), -time.Second)
	require.ErrorIs(t, err, auth.ErrInvalidRequest)
	purged, err := fixture.store.Purge(t.Context(), 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, int64(4), purged, "ended (the earlier of revoked and expired) more than a day ago")
	for _, key := range []*postgresstore.Key{revokedBeforeExpiry, expiredBeforeRevoked} {
		_, err = fixture.store.Get(t.Context(), key.ID)
		require.ErrorIs(t, err, postgresstore.ErrKeyNotFound, "a key ends at the earlier of its revocation and its expiry")
	}

	_, err = fixture.store.Get(t.Context(), revokedEarly.ID)
	require.ErrorIs(t, err, postgresstore.ErrKeyNotFound)
	_, err = fixture.store.Get(t.Context(), expiring.ID)
	require.ErrorIs(t, err, postgresstore.ErrKeyNotFound)
	keys, err := fixture.store.List(t.Context(), fixture.owner)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{active.ID, revokedLate.ID}, []uuid.UUID{keys[0].ID, keys[1].ID})
	purged, err = fixture.store.Purge(t.Context(), 0)
	require.NoError(t, err)
	require.Zero(t, purged, "a key revoked this instant is not older than retention 0")
	fixture.now = fixture.now.Add(time.Microsecond)
	purged, err = fixture.store.Purge(t.Context(), 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), purged, "retention 0 purges every key that ended before now")
}

// An administrator's view reaches every owner's keys; the application authorizes it.
func TestAdministratorView(t *testing.T) {
	fixture := newFixture(t)
	other := uuid.New()
	_, first := fixture.issue(t, tasksRead)
	_, second, err := fixture.store.Issue(t.Context(), other, postgresstore.IssueRequest{Name: "other", Scopes: []auth.Permission{tasksRead}})
	require.NoError(t, err)
	_, third := fixture.issue(t, tasksWrite)

	page, err := fixture.store.ListAll(t.Context(), uuid.Nil, 2)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{first.ID, second.ID}, []uuid.UUID{page[0].ID, page[1].ID})
	page, err = fixture.store.ListAll(t.Context(), page[1].ID, 2)
	require.NoError(t, err)
	require.Len(t, page, 1, "a short page is the last")
	require.Equal(t, third.ID, page[0].ID)
	for _, limit := range []int{0, -1, 1001} {
		_, err = fixture.store.ListAll(t.Context(), uuid.Nil, limit)
		require.ErrorIs(t, err, auth.ErrInvalidRequest, "limit %d", limit)
	}

	got, err := fixture.store.Get(t.Context(), second.ID)
	require.NoError(t, err)
	require.Equal(t, other, got.OwnerID)
	_, err = fixture.store.Get(t.Context(), uuid.New())
	require.ErrorIs(t, err, postgresstore.ErrKeyNotFound)

	revoked, revokedNow, err := fixture.store.RevokeAny(t.Context(), second.ID)
	require.NoError(t, err)
	require.True(t, revokedNow)
	require.Equal(t, other, revoked.OwnerID)
	require.False(t, revoked.RevokedAt.IsZero())
	again, revokedAgain, err := fixture.store.RevokeAny(t.Context(), second.ID)
	require.NoError(t, err)
	require.False(t, revokedAgain, "revoked before")
	require.True(t, revoked.RevokedAt.Equal(again.RevokedAt))
	_, _, err = fixture.store.RevokeAny(t.Context(), uuid.New())
	require.ErrorIs(t, err, postgresstore.ErrKeyNotFound)
}

// A Revoke waiting on the row lock of a revocation that then commits answers revoked=false with the other
// call's time, so only the first writes an audit entry.
func TestARevocationWaitingForAnotherSeesItsTime(t *testing.T) {
	fixture := newFixture(t)
	_, key := fixture.issue(t, tasksRead)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	transaction, err := fixture.pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = transaction.Rollback(context.Background()) }) // a no-op after the commit
	fixture.now = start.Add(time.Minute)
	first, revoked, err := fixture.store.WithExecutor(transaction).Revoke(ctx, fixture.owner, key.ID)
	require.NoError(t, err)
	require.True(t, revoked)
	fixture.now = start.Add(time.Hour) // before the goroutine starts, so it reads this time without a race

	type result struct {
		key     *postgresstore.Key
		revoked bool
		err     error
	}
	waiter := make(chan result, 1)
	go func() {
		key, revoked, err := fixture.store.Revoke(ctx, fixture.owner, key.ID)
		waiter <- result{key, revoked, err}
	}()
	for waiting := false; !waiting; {
		require.NoError(t, fixture.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting))
	}
	require.NoError(t, transaction.Commit(ctx))

	second := <-waiter
	require.NoError(t, second.err)
	require.False(t, second.revoked, "the other call revoked it")
	require.True(t, first.RevokedAt.Equal(second.key.RevokedAt), "the time of the revocation that committed")
}

// commitBefore runs commit before the executor's second QueryRow.
type commitBefore struct {
	postgresstore.Executor
	calls  int
	commit func()
}

func (e *commitBefore) QueryRow(ctx context.Context, statement string, arguments ...any) pgx.Row {
	if e.calls++; e.calls == 2 {
		e.commit()
	}
	return e.Executor.QueryRow(ctx, statement, arguments...)
}

// A key that commits between Revoke's update and its second statement was not there for the update:
// ErrKeyNotFound, never an unrevoked key with revoked=false.
func TestRevokeOfAKeyCommittingMeanwhileIsNotFound(t *testing.T) {
	fixture := newFixture(t)
	transaction, err := fixture.pool.Begin(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = transaction.Rollback(context.Background()) }) // a no-op after the commit
	_, key, err := fixture.store.WithExecutor(transaction).Issue(t.Context(), fixture.owner, postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{tasksRead}})
	require.NoError(t, err)
	executor := &commitBefore{Executor: fixture.pool, commit: func() { require.NoError(t, transaction.Commit(t.Context())) }}

	_, _, err = fixture.store.WithExecutor(executor).Revoke(t.Context(), fixture.owner, key.ID)
	require.ErrorIs(t, err, postgresstore.ErrKeyNotFound)
	require.Equal(t, 2, executor.calls, "the update and the second statement")
	got, err := fixture.store.Get(t.Context(), key.ID)
	require.NoError(t, err)
	require.True(t, got.RevokedAt.IsZero(), "the key committed after the update")
}

// singleConnectionPool is a pool that holds at most one connection: a statement that does not run on the
// transaction holding it waits for the context's deadline.
func singleConnectionPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	configuration, err := pgxpool.ParseConfig(postgres.Database(t))
	require.NoError(t, err)
	configuration.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), configuration)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// Every call of a WithExecutor view runs on the caller's transaction: on a pool of one connection, which the
// transaction holds, none waits for a second, and a rollback takes the key with it. Load gets the same
// executor, so Resolve reads an owner the transaction inserted.
func TestWithExecutorRunsEveryCallOnTheTransaction(t *testing.T) {
	fixture := newFixture(t)
	pool := singleConnectionPool(t)
	loadFromUsers := func(ctx context.Context, executor postgresstore.Executor, ownerID uuid.UUID) (*auth.Identity, error) {
		var username string
		if err := executor.QueryRow(ctx, `SELECT username FROM users WHERE id = $1`, ownerID).Scan(&username); err != nil {
			return nil, err
		}
		return &auth.Identity{Username: username, Active: true, Permissions: []auth.Permission{allWrite}}, nil
	}
	store, err := postgresstore.New(&postgresstore.Options{Pool: pool, Prefix: "todo", Load: loadFromUsers})
	require.NoError(t, err)
	postgresstore.SetClock(store, func() time.Time { return fixture.now })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	transaction, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = transaction.Rollback(context.Background()) }) // a no-op after the explicit rollback
	_, err = transaction.Exec(ctx, `CREATE TABLE users (id uuid PRIMARY KEY, username text NOT NULL)`)
	require.NoError(t, err)
	_, err = transaction.Exec(ctx, `INSERT INTO users VALUES ($1, 'ada')`, fixture.owner)
	require.NoError(t, err)
	view := store.WithExecutor(transaction)

	text, key, err := view.Issue(ctx, fixture.owner, postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{tasksRead}})
	require.NoError(t, err)
	identity, err := view.Resolve(ctx, text)
	require.NoError(t, err, "Resolve, its Load and its last-use write")
	require.Equal(t, "ada", identity.Username, "the owner the transaction inserted")
	keys, err := view.List(ctx, fixture.owner)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.True(t, start.Equal(keys[0].LastUsedAt))
	_, err = view.Get(ctx, key.ID)
	require.NoError(t, err)
	page, err := view.ListAll(ctx, uuid.Nil, 10)
	require.NoError(t, err)
	require.Len(t, page, 1)
	_, revoked, err := view.Revoke(ctx, fixture.owner, key.ID)
	require.NoError(t, err)
	require.True(t, revoked)
	_, revoked, err = view.RevokeAny(ctx, key.ID)
	require.NoError(t, err)
	require.False(t, revoked, "the same transaction revoked it")
	purged, err := view.Purge(ctx, 0)
	require.NoError(t, err)
	require.Equal(t, int64(0), purged, "revoked at start, purged only before it")
	require.NoError(t, transaction.Rollback(ctx))

	keys, err = store.List(ctx, fixture.owner)
	require.NoError(t, err)
	require.Empty(t, keys, "the key rolled back with the transaction")
	keys, err = store.WithExecutor(nil).List(ctx, fixture.owner)
	require.NoError(t, err, "a nil executor is the pool")
	require.Empty(t, keys)
}

// An application's foreign key on owner_id: Issue answers a missing owner with ErrOwnerNotFound and keeps
// PostgreSQL's error; on a transaction it sees an owner inserted before it.
func TestIssueChecksTheApplicationsForeignKey(t *testing.T) {
	fixture := newFixture(t)
	for _, statement := range []string{
		`CREATE TABLE users (id uuid PRIMARY KEY)`,
		`ALTER TABLE govengers_auth_api_keys ADD FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE RESTRICT`,
	} {
		_, err := fixture.pool.Exec(t.Context(), statement)
		require.NoError(t, err)
	}
	request := postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{tasksRead}}

	_, _, err := fixture.store.Issue(t.Context(), fixture.owner, request)
	require.ErrorIs(t, err, postgresstore.ErrOwnerNotFound)
	var postgresError *pgconn.PgError
	require.ErrorAs(t, err, &postgresError)
	require.Equal(t, "23503", postgresError.Code)

	transaction, err := fixture.pool.Begin(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = transaction.Rollback(context.Background()) }) // a no-op after the commit
	_, err = transaction.Exec(t.Context(), `INSERT INTO users (id) VALUES ($1)`, fixture.owner)
	require.NoError(t, err)
	_, key, err := fixture.store.WithExecutor(transaction).Issue(t.Context(), fixture.owner, request)
	require.NoError(t, err, "the key's foreign key sees the uncommitted owner")
	require.NoError(t, transaction.Commit(t.Context()))
	got, err := fixture.store.Get(t.Context(), key.ID)
	require.NoError(t, err)
	require.Equal(t, fixture.owner, got.OwnerID)
}

// The store is the Resolver of an apikey.Authenticator: a valid key reaches the handler as its owner,
// a revoked one is answered 401 invalid_api_key.
func TestStoreBehindTheAuthenticator(t *testing.T) {
	fixture := newFixture(t)
	text, key := fixture.issue(t, tasksRead)
	authenticator, err := apikey.New(&apikey.Options{Resolver: fixture.store.Resolve})
	require.NoError(t, err)
	handler := authenticator.Middleware()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := auth.IdentityFrom(request.Context())
		if !identity.Permits("tasks", auth.AccessRead) || identity.Permits("tasks", auth.AccessWrite) {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	send := func() *httptest.ResponseRecorder {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/tasks", nil)
		request.Header.Set("Authorization", "Bearer "+text)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	require.Equal(t, http.StatusNoContent, send().Code)
	_, _, err = fixture.store.Revoke(t.Context(), fixture.owner, key.ID)
	require.NoError(t, err)
	refused := send()
	require.Equal(t, http.StatusUnauthorized, refused.Code)
	require.Contains(t, refused.Body.String(), "invalid_api_key")
}

func TestIntersect(t *testing.T) {
	notes := auth.Permission{Resource: "notes", Access: auth.AccessWrite}
	testCases := []struct {
		name    string
		granted []auth.Permission
		scopes  []auth.Permission
		want    []auth.Permission
	}{
		{name: "all write narrowed to a resource", granted: []auth.Permission{allWrite}, scopes: []auth.Permission{tasksRead}, want: []auth.Permission{tasksRead}},
		{name: "resource narrowed by all read", granted: []auth.Permission{tasksWrite}, scopes: []auth.Permission{allRead}, want: []auth.Permission{tasksRead}},
		{name: "disjoint resources", granted: []auth.Permission{tasksWrite}, scopes: []auth.Permission{notes}, want: nil},
		{name: "same resource keeps write", granted: []auth.Permission{tasksWrite}, scopes: []auth.Permission{tasksWrite}, want: []auth.Permission{tasksWrite}},
		{name: "duplicates once", granted: []auth.Permission{allWrite, tasksWrite}, scopes: []auth.Permission{tasksRead}, want: []auth.Permission{tasksRead}},
		{name: "invalid granted permission grants nothing", granted: []auth.Permission{{Resource: "Tasks", Access: auth.AccessWrite}}, scopes: []auth.Permission{allWrite}, want: nil},
		{name: "no permissions", granted: nil, scopes: []auth.Permission{allWrite}, want: nil},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := postgresstore.Intersect(testCase.granted, testCase.scopes)
			require.Equal(t, testCase.want, got)
			for _, resource := range []string{"tasks", "notes", "other"} {
				for _, access := range []auth.Access{auth.AccessRead, auth.AccessWrite} {
					both := (&auth.Identity{Permissions: testCase.granted}).Permits(resource, access) &&
						(&auth.Identity{Permissions: testCase.scopes}).Permits(resource, access)
					require.Equal(t, both, (&auth.Identity{Permissions: got}).Permits(resource, access), "%s:%s", resource, access)
				}
			}
		})
	}
}

// A database error keeps pgx's error in its chain (part of the API), so the application maps it.
func TestErrorsKeepThePostgreSQLError(t *testing.T) {
	fixture := newFixture(t)
	text, key := fixture.issue(t, tasksRead)
	_, err := fixture.pool.Exec(t.Context(), `DROP TABLE govengers_auth_api_keys`)
	require.NoError(t, err)
	ctx := t.Context()
	requireUndefinedTable := func(err error, operation string) {
		t.Helper()
		require.ErrorContains(t, err, "postgres api key store: "+operation)
		var postgresError *pgconn.PgError
		require.ErrorAs(t, err, &postgresError)
		require.Equal(t, "42P01", postgresError.Code)
	}

	_, _, err = fixture.store.Issue(ctx, fixture.owner, postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{tasksRead}})
	requireUndefinedTable(err, "issue key")
	require.NotErrorIs(t, err, postgresstore.ErrOwnerNotFound)
	_, err = fixture.store.List(ctx, fixture.owner)
	requireUndefinedTable(err, "list keys")
	_, err = fixture.store.ListAll(ctx, uuid.Nil, 10)
	requireUndefinedTable(err, "list all keys")
	_, err = fixture.store.Get(ctx, key.ID)
	requireUndefinedTable(err, "get key")
	_, _, err = fixture.store.Revoke(ctx, fixture.owner, key.ID)
	requireUndefinedTable(err, "revoke key")
	_, err = fixture.store.Purge(ctx, time.Hour)
	requireUndefinedTable(err, "purge keys")
	_, err = fixture.store.Resolve(ctx, text)
	requireUndefinedTable(err, "read key")
	require.NotErrorIs(t, err, auth.ErrUnauthenticated)
	_, err = fixture.store.Resolve(ctx, "todo_malformed")
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "the shape is checked before any query")
}

// A failed last-use write refuses the request and keeps its cause.
func TestAFailedLastUseWriteKeepsItsCause(t *testing.T) {
	fixture := newFixture(t)
	text, _ := fixture.issue(t, tasksRead)
	transaction, err := fixture.pool.BeginTx(t.Context(), pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	t.Cleanup(func() { _ = transaction.Rollback(context.Background()) })

	_, err = fixture.store.WithExecutor(transaction).Resolve(t.Context(), text)

	require.ErrorContains(t, err, "postgres api key store: record key use")
	var postgresError *pgconn.PgError
	require.ErrorAs(t, err, &postgresError)
	require.Equal(t, "25006", postgresError.Code, "read-only transaction")
}
