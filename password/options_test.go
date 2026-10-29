package password

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/session"
)

func testSessions(t *testing.T) *session.Store {
	t.Helper()
	backend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	sessions, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: testEncryptionKey})
	require.NoError(t, err)
	return sessions
}

func TestNewRefusesInvalidOptions(t *testing.T) {
	sessions := testSessions(t)
	storage := NewMemoryStorage()
	valid := func(change func(options *Options)) *Options {
		options := &Options{Sessions: sessions, Storage: storage}
		change(options)
		return options
	}
	enabledTOTP := func(change func(options *TOTPOptions)) *Options {
		return valid(func(options *Options) {
			options.TOTP = TOTPOptions{Enabled: true, Issuer: "Example"}
			change(&options.TOTP)
		})
	}
	testCases := []struct {
		name    string
		options *Options
	}{
		{name: "nil options", options: nil},
		{name: "no sessions", options: valid(func(options *Options) { options.Sessions = nil })},
		{name: "no storage", options: valid(func(options *Options) { options.Storage = nil })},
		{name: "relative prefix", options: valid(func(options *Options) { options.PathPrefix = "auth" })},
		{name: "root prefix", options: valid(func(options *Options) { options.PathPrefix = "/" })},
		{name: "trailing slash", options: valid(func(options *Options) { options.PathPrefix = "/auth/" })},
		{name: "unclean prefix", options: valid(func(options *Options) { options.PathPrefix = "/auth//password" })},
		{name: "dot segment prefix", options: valid(func(options *Options) { options.PathPrefix = "/auth/../password" })},
		{name: "prefix with a space", options: valid(func(options *Options) { options.PathPrefix = "/auth/pass word" })},
		{name: "prefix with a wildcard", options: valid(func(options *Options) { options.PathPrefix = "/auth/{provider}" })},
		{name: "prefix with a query", options: valid(func(options *Options) { options.PathPrefix = "/auth?x=1" })},
		{name: "no login left", options: valid(func(options *Options) { options.DisableUsernameLogin, options.DisableEmailLogin = true, true })},
		{name: "negative minimum length", options: valid(func(options *Options) { options.Policy.MinimumLength = -1 })},
		{name: "minimum length above 128", options: valid(func(options *Options) { options.Policy.MinimumLength = 129 })},
		{name: "hash memory below the floor", options: valid(func(options *Options) { options.HashParameters = testParameters })},
		{name: "hash parameters above the limit", options: valid(func(options *Options) {
			options.HashParameters = DefaultParameters()
			options.HashParameters.Iterations = 51
		})},
		{name: "TOTP required but not enabled", options: valid(func(options *Options) { options.TOTP.Required = true })},
		{name: "TOTP without issuer", options: enabledTOTP(func(options *TOTPOptions) { options.Issuer = "" })},
		{name: "TOTP with 7 digits", options: enabledTOTP(func(options *TOTPOptions) { options.Digits = 7 })},
		{name: "TOTP period above an hour", options: enabledTOTP(func(options *TOTPOptions) { options.Period = 3601 })},
		{name: "TOTP skew above 10", options: enabledTOTP(func(options *TOTPOptions) { options.Skew = 11 })},
		{name: "negative attempts", options: enabledTOTP(func(options *TOTPOptions) { options.MaximumAttempts = -1 })},
		{name: "negative pending TTL", options: enabledTOTP(func(options *TOTPOptions) { options.PendingTTL = -time.Second })},
		{name: "negative backup code count", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeCount = -1 })},
		{name: "negative backup code length", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeLength = -1 })},
		{name: "alphabet of one character", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeAlphabet = "aaaa" })},
		{name: "alphabet that collapses to one character", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeAlphabet = "Aa" })},
		{name: "alphabet with a space", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeAlphabet = "ab c" })},
		{name: "backup codes longer than a hash accepts", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeLength = 129 })},
		{name: "multibyte backup codes longer than a hash accepts", options: enabledTOTP(func(options *TOTPOptions) {
			options.BackupCodeAlphabet = "äöü"
			options.BackupCodeLength = 65
		})},
		{name: "backup codes of one character", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeLength = 1 })},
		{name: "fewer than a million backup codes", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeLength = 5 })},
		{name: "more than 20 backup codes", options: enabledTOTP(func(options *TOTPOptions) { options.BackupCodeCount = 21 })},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider, err := New(testCase.options)
			require.Error(t, err)
			require.Nil(t, provider)
		})
	}
}

func TestResolveOptionsAppliesDefaults(t *testing.T) {
	options := Options{Sessions: testSessions(t), Storage: NewMemoryStorage(), TOTP: TOTPOptions{Enabled: true, Issuer: "Example", BackupCodeAlphabet: "ABCdef"}}
	original := options

	resolved, err := resolveOptions(options)
	require.NoError(t, err)

	require.Equal(t, original, options)
	require.Equal(t, "/auth/password", resolved.PathPrefix)
	require.Equal(t, 12, resolved.Policy.MinimumLength)
	require.Equal(t, DefaultParameters(), resolved.HashParameters)
	require.Equal(t, TOTPOptions{
		Enabled: true, Issuer: "Example", Period: 30, Digits: 6, Skew: 1, MaximumAttempts: 5, PendingTTL: 5 * time.Minute,
		BackupCodeCount: 10, BackupCodeLength: 10, BackupCodeAlphabet: "abcdef",
	}, resolved.TOTP)
}

func TestNewAcceptsTheSmallestBackupCodes(t *testing.T) {
	testCases := []struct {
		name         string
		alphabet     string
		length       int
		wantAlphabet string
	}{
		{name: "a million codes of 6 digits", alphabet: "0123456789", length: 6, wantAlphabet: "0123456789"},
		{name: "128 bytes of multibyte characters", alphabet: "äöü", length: 64, wantAlphabet: "äöü"},
		{name: "repeated characters count once", alphabet: "aAb", length: 20, wantAlphabet: "ab"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider, err := New(&Options{Sessions: testSessions(t), Storage: NewMemoryStorage(), TOTP: TOTPOptions{
				Enabled: true, Issuer: "Example", BackupCodeAlphabet: testCase.alphabet, BackupCodeLength: testCase.length,
			}})
			require.NoError(t, err)
			require.Equal(t, testCase.wantAlphabet, string(provider.backupCodeAlphabet))
		})
	}
}

func TestNewKeepsItsOwnCopy(t *testing.T) {
	floor := Parameters{Memory: 32 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16}
	options := &Options{Sessions: testSessions(t), Storage: NewMemoryStorage(), PathPrefix: "/login", HashParameters: floor}
	original := *options

	provider, err := New(options)
	require.NoError(t, err)
	require.Equal(t, original, *options)

	options.PathPrefix = "/changed"
	require.Equal(t, "/login/login", provider.Routes()[0].Path)
	require.Equal(t, "password", provider.Name())
	matched, err := Verify("anything", provider.dummyHash)
	require.NoError(t, err)
	require.False(t, matched)
}

func TestRoutes(t *testing.T) {
	testCases := []struct {
		name    string
		options Options
		want    []string
	}{
		{name: "defaults", want: []string{"POST /auth/password/login", "POST /auth/password/logout"}},
		{name: "registration", options: Options{EnableRegistration: true}, want: []string{"POST /auth/password/login", "POST /auth/password/logout", "POST /auth/password/register"}},
		{name: "TOTP and a prefix", options: Options{PathPrefix: "/api/auth", TOTP: TOTPOptions{Enabled: true, Issuer: "Example"}}, want: []string{
			"POST /api/auth/login", "POST /api/auth/logout", "POST /api/auth/totp/verify", "GET /api/auth/totp",
			"POST /api/auth/totp/setup", "POST /api/auth/totp/enable", "POST /api/auth/totp/disable",
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			routes := newFixture(t, testCase.options).provider.Routes()
			patterns := make([]string, 0, len(routes))
			for _, route := range routes {
				require.NotNil(t, route.Handler)
				patterns = append(patterns, route.Method+" "+route.Path)
			}
			require.Equal(t, testCase.want, patterns)
		})
	}
}

func TestDisabledRoutesAreNotRouted(t *testing.T) {
	fixture := newFixture(t, Options{})
	browser := fixture.newClient(t)
	for _, path := range []string{"/auth/password/register", "/auth/password/totp/setup", "/auth/password/totp/verify"} {
		require.Equal(t, http.StatusNotFound, browser.post(path, map[string]any{}).Code, path)
	}
	require.Empty(t, fixture.outcomes.take())
}
