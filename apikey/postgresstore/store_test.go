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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/apikey/postgresstore"
	"github.com/govengers/auth/internal/postgrestest"
)

func TestMain(m *testing.M) { postgrestest.Main(m) }

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
	pool := postgrestest.New(t, postgresstore.MigrationV1)
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

func (f *fixture) load(_ context.Context, ownerID uuid.UUID) (*auth.Identity, error) {
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
	pool := postgrestest.New(t)
	load := func(context.Context, uuid.UUID) (*auth.Identity, error) { return nil, nil }
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
		Name: "ci", Scopes: []auth.Permission{tasksRead}, ExpiresAt: start.Add(time.Hour),
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
	require.NoError(t, fixture.store.Revoke(t.Context(), fixture.owner, revokedKey.ID))
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
		{name: "revoked", key: revoked, reason: "unknown key"},
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
	pool := postgrestest.New(t, postgresstore.MigrationV1)
	owner := uuid.New()
	var loadError error
	var loaded *auth.Identity
	store, err := postgresstore.New(&postgresstore.Options{Pool: pool, Prefix: "todo", Load: func(context.Context, uuid.UUID) (*auth.Identity, error) {
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

	require.ErrorIs(t, fixture.store.Revoke(t.Context(), other, first.ID), postgresstore.ErrKeyNotFound)
	require.NoError(t, fixture.store.Revoke(t.Context(), fixture.owner, first.ID))
	require.ErrorIs(t, fixture.store.Revoke(t.Context(), fixture.owner, first.ID), postgresstore.ErrKeyNotFound)
	keys, err = fixture.store.List(t.Context(), fixture.owner)
	require.NoError(t, err)
	require.Len(t, keys, 1)
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
	require.NoError(t, fixture.store.Revoke(t.Context(), fixture.owner, key.ID))
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

func TestErrorsAreReportedWithoutTheirChain(t *testing.T) {
	fixture := newFixture(t)
	text, key := fixture.issue(t, tasksRead)
	fixture.pool.Close()
	ctx := context.Background()

	_, _, err := fixture.store.Issue(ctx, fixture.owner, postgresstore.IssueRequest{Name: "ci", Scopes: []auth.Permission{tasksRead}})
	require.ErrorContains(t, err, "postgres api key store: issue key")
	_, err = fixture.store.List(ctx, fixture.owner)
	require.ErrorContains(t, err, "postgres api key store: list keys")
	require.ErrorContains(t, fixture.store.Revoke(ctx, fixture.owner, key.ID), "postgres api key store: revoke key")
	_, err = fixture.store.Resolve(ctx, text)
	require.ErrorContains(t, err, "postgres api key store: read key")
	require.NotErrorIs(t, err, auth.ErrUnauthenticated)
	_, err = fixture.store.Resolve(ctx, "todo_malformed")
	require.ErrorIs(t, err, auth.ErrUnauthenticated, "the shape is checked before any query")
}
