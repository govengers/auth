package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
)

const (
	realm         = "staff"
	userID        = "5d3f6e2a-1b2c-4d5e-8f90-123456789abc"
	appClientID   = "app"
	serviceClient = "app-admin"
	serviceSecret = "service-secret"
)

// fakeKeycloak is the fake issuer in Keycloak layout, with the base URL keycloak.Options.URL needs.
type fakeKeycloak struct {
	*fakeprovider.OIDCHandler
	url string
}

// startKeycloak serves a fake realm "staff" whose user carries roles, groups and attributes; configure
// changes the options, wrap the handler.
func startKeycloak(t *testing.T, configure func(options *fakeprovider.OIDCOptions), wrap func(next http.Handler) http.Handler) *fakeKeycloak {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	base := "http://" + server.Listener.Addr().String()
	options := fakeprovider.OIDCOptions{
		IssuerURL: base + "/realms/" + realm, ClientID: appClientID, ClientSecret: "app-secret",
		KeycloakRealm: realm, KeycloakClientID: serviceClient, KeycloakClientSecret: serviceSecret,
		User: fakeprovider.OIDCUser{
			Subject: userID, PreferredUsername: "ada",
			RealmRoles: []string{"default-roles-staff", "admin"}, ClientRoles: []string{"editor"},
			Groups: []string{"/staff", "/staff/scoring"}, Attributes: map[string][]string{"team": {"chassis"}},
		},
	}
	if configure != nil {
		configure(&options)
	}
	handler, err := fakeprovider.NewOIDCHandler(&options)
	require.NoError(t, err)
	var served http.Handler = handler
	if wrap != nil {
		served = wrap(handler)
	}
	server.Config.Handler = served
	server.Start()
	t.Cleanup(server.Close)
	return &fakeKeycloak{OIDCHandler: handler, url: base}
}

func newClient(t *testing.T, keycloak *fakeKeycloak, configure func(options *Options)) *Client {
	t.Helper()
	options := &Options{URL: keycloak.url, Realm: realm, ClientID: serviceClient, ClientSecret: serviceSecret, ClientRolesClientID: appClientID}
	if configure != nil {
		configure(options)
	}
	client, err := New(options)
	require.NoError(t, err)
	return client
}

func loginIdentity() *auth.Identity {
	return &auth.Identity{
		Provider: "keycloak", Subject: userID, Username: "ada", Email: "ada@example.com", Active: true,
		Roles: []string{"app-role"}, OIDCRoles: []string{"from-token"}, Groups: []string{"/from-token"},
	}
}

func TestNewValidatesOptions(t *testing.T) {
	testCases := []struct {
		name    string
		options *Options
	}{
		{name: "nil", options: nil},
		{name: "no URL", options: &Options{Realm: realm, ClientID: serviceClient, ClientSecret: serviceSecret}},
		{name: "plain HTTP URL", options: &Options{URL: "http://keycloak.example.com", Realm: realm, ClientID: serviceClient, ClientSecret: serviceSecret}},
		{name: "URL with query", options: &Options{URL: "https://keycloak.example.com?x=1", Realm: realm, ClientID: serviceClient, ClientSecret: serviceSecret}},
		{name: "no realm", options: &Options{URL: "https://keycloak.example.com", ClientID: serviceClient, ClientSecret: serviceSecret}},
		{name: "client credentials without secret", options: &Options{URL: "https://keycloak.example.com", Realm: realm, ClientID: serviceClient}},
		{name: "client credentials without client", options: &Options{URL: "https://keycloak.example.com", Realm: realm, ClientSecret: serviceSecret}},
		{name: "password without password", options: &Options{URL: "https://keycloak.example.com", Realm: realm, GrantType: GrantTypePassword, Username: "admin"}},
		{name: "unknown grant", options: &Options{URL: "https://keycloak.example.com", Realm: realm, GrantType: "implicit", ClientID: serviceClient, ClientSecret: serviceSecret}},
		{name: "required client roles without client", options: &Options{URL: "https://keycloak.example.com", Realm: realm, ClientID: serviceClient, ClientSecret: serviceSecret, RequiredClientRoles: []string{"editor"}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := New(testCase.options)

			require.Error(t, err)
			require.NotContains(t, err.Error(), serviceSecret)
		})
	}
}

func TestNewAppliesDefaultsToACopy(t *testing.T) {
	options := &Options{URL: "https://keycloak.example.com/", Realm: realm, GrantType: GrantTypePassword, Username: "admin", Password: "admin-password", RequiredGroups: []string{"/staff"}}
	before := *options

	client, err := New(options)

	require.NoError(t, err)
	require.Equal(t, before, *options, "options untouched")
	require.Equal(t, "https://keycloak.example.com", client.options.URL)
	require.Equal(t, realm, client.options.AuthenticationRealm)
	require.Equal(t, "admin-cli", client.options.ClientID)
	options.RequiredGroups[0] = "/changed"
	require.Equal(t, []string{"/staff"}, client.options.RequiredGroups)

	defaults, err := New(&Options{URL: "https://keycloak.example.com", Realm: realm, ClientID: serviceClient, ClientSecret: serviceSecret})
	require.NoError(t, err)
	require.Equal(t, GrantTypeClientCredentials, defaults.options.GrantType)
	require.NotNil(t, defaults.options.HTTPClient)
}

func TestEnrichReplacesRolesGroupsAndAttributes(t *testing.T) {
	testCases := []struct {
		name            string
		clientRoles     string
		wantClientRoles []string
		wantLookups     int
	}{
		{name: "with client roles", clientRoles: appClientID, wantClientRoles: []string{"editor"}, wantLookups: 1},
		{name: "without client roles", clientRoles: "", wantClientRoles: nil, wantLookups: 0},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			keycloak := startKeycloak(t, nil, nil)
			client := newClient(t, keycloak, func(options *Options) { options.ClientRolesClientID = testCase.clientRoles })
			identity := loginIdentity()

			enriched, err := client.Enrich(t.Context(), identity)

			require.NoError(t, err)
			want := loginIdentity()
			want.OIDCRoles = []string{"default-roles-staff", "admin"}
			want.OIDCClientRoles = testCase.wantClientRoles
			want.Groups = []string{"/staff", "/staff/scoring"}
			want.Attributes = map[string][]string{"team": {"chassis"}}
			require.Equal(t, want, enriched)
			require.Equal(t, loginIdentity(), identity, "the argument is not changed")
			require.Equal(t, testCase.wantLookups, keycloak.KeycloakClientLookups())
		})
	}
}

func TestEnrichWithThePasswordGrantInTheAuthenticationRealm(t *testing.T) {
	keycloak := startKeycloak(t, func(options *fakeprovider.OIDCOptions) {
		options.KeycloakAuthenticationRealm = "master"
		options.KeycloakUsername, options.KeycloakPassword = "admin", "admin-password"
	}, nil)
	testCases := []struct {
		name                string
		authenticationRealm string
		wantError           bool
	}{
		{name: "master realm", authenticationRealm: "master", wantError: false},
		{name: "users' realm", authenticationRealm: "", wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newClient(t, keycloak, func(options *Options) {
				options.GrantType, options.Username, options.Password = GrantTypePassword, "admin", "admin-password"
				options.ClientID, options.ClientSecret = "", ""
				options.AuthenticationRealm = testCase.authenticationRealm
			})

			_, err := client.Enrich(t.Context(), loginIdentity())

			require.Equal(t, testCase.wantError, err != nil, err)
		})
	}
}

func TestTheTokenIsCachedUntil30SecondsBeforeExpiry(t *testing.T) {
	keycloak := startKeycloak(t, nil, nil)
	client := newClient(t, keycloak, nil)
	clock := &testClock{current: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	client.now = clock.now

	steps := []struct {
		advance      time.Duration
		wantRequests int
	}{
		{advance: 0, wantRequests: 1},
		{advance: 269 * time.Second, wantRequests: 1},
		{advance: time.Second, wantRequests: 2}, // 300 s lifetime minus 30 s
		{advance: time.Minute, wantRequests: 2},
	}
	for _, step := range steps {
		clock.advance(step.advance)

		_, err := client.Enrich(t.Context(), loginIdentity())

		require.NoError(t, err)
		require.Equal(t, step.wantRequests, keycloak.KeycloakTokenRequests())
	}
	require.Equal(t, 1, keycloak.KeycloakClientLookups(), "the client UUID is cached")
}

func TestAFailedClientLookupIsRetriedByTheNextLogin(t *testing.T) {
	failures := &failFirst{path: "/admin/realms/" + realm + "/clients"}
	keycloak := startKeycloak(t, nil, failures.wrap)
	client := newClient(t, keycloak, nil)

	_, err := client.Enrich(t.Context(), loginIdentity())
	require.Error(t, err)
	enriched, err := client.Enrich(t.Context(), loginIdentity())
	require.NoError(t, err)

	require.Equal(t, []string{"editor"}, enriched.OIDCClientRoles)
}

func TestEnrichRefusesMissingRequirements(t *testing.T) {
	keycloak := startKeycloak(t, nil, nil)
	testCases := []struct {
		name       string
		configure  func(options *Options)
		wantReason string
	}{
		{name: "all present", configure: func(options *Options) {
			options.RequiredRealmRoles, options.RequiredClientRoles, options.RequiredGroups = []string{"admin"}, []string{"editor"}, []string{"/staff/scoring"}
		}},
		{name: "realm role", configure: func(options *Options) { options.RequiredRealmRoles = []string{"admin", "auditor"} }, wantReason: "missing realm role auditor"},
		{name: "client role", configure: func(options *Options) { options.RequiredClientRoles = []string{"publisher"} }, wantReason: "missing client role publisher"},
		{name: "group", configure: func(options *Options) { options.RequiredGroups = []string{"/staff/board"} }, wantReason: "missing group /staff/board"},
		{name: "group by name instead of path", configure: func(options *Options) { options.RequiredGroups = []string{"scoring"} }, wantReason: "missing group scoring"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newClient(t, keycloak, testCase.configure)

			enriched, err := client.Enrich(t.Context(), loginIdentity())

			if testCase.wantReason == "" {
				require.NoError(t, err)
				require.NotNil(t, enriched)
				return
			}
			var refusal *auth.Error
			require.ErrorAs(t, err, &refusal)
			require.ErrorIs(t, err, auth.ErrForbidden)
			require.Equal(t, testCase.wantReason, refusal.Reason)
			_, response := auth.ResponseFor(err)
			require.Equal(t, auth.ErrorResponse{Code: "forbidden", Message: "access denied"}, response, "the reason stays server-side")
		})
	}
}

func TestEnrichFailuresArePlainErrors(t *testing.T) {
	keycloak := startKeycloak(t, nil, nil)
	unreachable := &fakeKeycloak{url: "http://127.0.0.1:1"}
	testCases := []struct {
		name      string
		keycloak  *fakeKeycloak
		configure func(options *Options)
		identity  *auth.Identity
	}{
		{name: "unknown user", keycloak: keycloak, identity: &auth.Identity{Subject: "someone-else"}},
		{name: "wrong service secret", keycloak: keycloak, configure: func(options *Options) { options.ClientSecret = "wrong" }, identity: loginIdentity()},
		{name: "unknown client roles client", keycloak: keycloak, configure: func(options *Options) { options.ClientRolesClientID = "other" }, identity: loginIdentity()},
		{name: "unreachable", keycloak: unreachable, identity: loginIdentity()},
		{name: "no subject", keycloak: keycloak, identity: &auth.Identity{}},
		{name: "no identity", keycloak: keycloak, identity: nil},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client := newClient(t, testCase.keycloak, testCase.configure)

			_, err := client.Enrich(t.Context(), testCase.identity)

			require.Error(t, err)
			status, _ := auth.ResponseFor(err)
			require.Equal(t, http.StatusInternalServerError, status)
			require.NotContains(t, err.Error(), serviceSecret)
			require.NotContains(t, err.Error(), "wrong")
		})
	}
}

func TestEnrichKeepsTheCancellationOfAnAdminAPICall(t *testing.T) {
	client := newClient(t, startKeycloak(t, nil, nil), nil)
	_, err := client.Enrich(t.Context(), loginIdentity())
	require.NoError(t, err, "caches the admin token, so the next call goes straight to the admin API")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = client.Enrich(ctx, loginIdentity())

	require.ErrorIs(t, err, context.Canceled)
}

func TestEnrichIsSafeForConcurrentUse(t *testing.T) {
	keycloak := startKeycloak(t, nil, nil)
	client := newClient(t, keycloak, nil)
	var group sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			_, err := client.Enrich(t.Context(), loginIdentity())
			results <- err
		})
	}
	group.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	require.Equal(t, 1, keycloak.KeycloakTokenRequests())
}

type testClock struct {
	mutex   sync.Mutex
	current time.Time
}

func (c *testClock) now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.current
}

func (c *testClock) advance(duration time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.current = c.current.Add(duration)
}

// failFirst answers the first request to path with 503.
type failFirst struct {
	path   string
	mutex  sync.Mutex
	failed bool
}

func (f *failFirst) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		f.mutex.Lock()
		fail := !f.failed && request.URL.Path == f.path
		f.failed = f.failed || fail
		f.mutex.Unlock()
		if fail {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(writer, request)
	})
}
