package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
)

const (
	testEncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // base64 of 32 bytes
	testSecret        = "ci-secret-0123456789"
)

// validOIDCConfiguration is what loadConfiguration returns for a minimal valid OIDC setup (defaults included).
func validOIDCConfiguration() *Configuration {
	return &Configuration{
		Provider: providerOIDC, ExternalURL: "https://app.example.com", PathPrefix: "/auth",
		Port: 8080, MetricsPort: 9090, WideEventSampleRate: 10, ShutdownDelaySeconds: 5,
		SessionEncryptionKey: testEncryptionKey, SessionCookieName: "forwardauth_session", SessionSameSite: "lax",
		SessionMaximumAgeSeconds: 86400, SessionRefreshIntervalSeconds: 60, SessionRedisKeyPrefix: "forwardauth",
		OIDCName: "oidc", OIDCIssuer: "https://idp.example.com", OIDCClientID: "forwardauth", OIDCClientSecret: "client-secret",
		OIDCScopes: []string{"openid", "profile", "email"}, OIDCClaimMapper: claimMapperDefault,
		KeycloakGrantType: grantTypeClientCredentials, GitHubScopes: []string{"read:org"},
		JWTLifetimeSeconds: 300, JWTHeader: "Authorization",
	}
}

func validGitHubConfiguration() *Configuration {
	configuration := validOIDCConfiguration()
	configuration.Provider = providerGitHub
	configuration.OIDCIssuer, configuration.OIDCClientID, configuration.OIDCClientSecret = "", "", ""
	configuration.GitHubClientID, configuration.GitHubClientSecret = "github-client", "github-secret"
	configuration.GitHubAllowedTeams = []string{"govengers/maintainers"}
	return configuration
}

func TestValidateConfigurationAcceptsCompleteSetups(t *testing.T) {
	testCases := []struct {
		name          string
		configuration func() *Configuration
	}{
		{name: "oidc", configuration: validOIDCConfiguration},
		{name: "github", configuration: validGitHubConfiguration},
		{name: "oidc with keycloak (client credentials), redis, jwt and api keys", configuration: func() *Configuration {
			configuration := validOIDCConfiguration()
			configuration.KeycloakEnabled = true
			configuration.KeycloakURL, configuration.KeycloakRealm = "https://keycloak.example.com", "company"
			configuration.KeycloakClientID, configuration.KeycloakClientSecret = "forwardauth", "keycloak-secret"
			configuration.SessionRedisEnabled, configuration.SessionRedisAddress = true, "redis:6379"
			configuration.JWTEnabled, configuration.JWTPrivateKey = true, "-----BEGIN PRIVATE KEY-----"
			configuration.APIKeys = []string{"ci:" + testSecret}
			configuration.APIKeyPermissions = []string{"ci=builds:write+*:read"}
			configuration.SessionSameSite = "none"
			return configuration
		}},
		{name: "keycloak with the password grant", configuration: func() *Configuration {
			configuration := validOIDCConfiguration()
			configuration.KeycloakEnabled, configuration.KeycloakGrantType = true, grantTypePassword
			configuration.KeycloakURL, configuration.KeycloakRealm = "https://keycloak.example.com", "company"
			configuration.KeycloakUsername, configuration.KeycloakPassword = "admin", "admin-password"
			return configuration
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.NoError(t, validateConfiguration(testCase.configuration()))
		})
	}
}

func TestValidateConfigurationNamesEveryProblem(t *testing.T) {
	testCases := []struct {
		name          string
		configuration func() *Configuration
		change        func(configuration *Configuration)
		problems      []string
	}{
		{name: "unknown provider", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.Provider = "password" }, problems: []string{"PROVIDER"}},
		{name: "relative external URL", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.ExternalURL = "app.example.com" }, problems: []string{"EXTERNAL_URL"}},
		{name: "external URL with a query", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.ExternalURL = "https://app.example.com/?a=b" }, problems: []string{"EXTERNAL_URL"}},
		{name: "path prefix without leading slash", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.PathPrefix = "auth" }, problems: []string{"PATH_PREFIX"}},
		{name: "path prefix with trailing slash", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.PathPrefix = "/auth/" }, problems: []string{"PATH_PREFIX"}},
		{name: "path prefix with a gin parameter", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.PathPrefix = "/auth/:tenant" }, problems: []string{"PATH_PREFIX"}},
		{name: "path prefix with an empty segment", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.PathPrefix = "/auth//x" }, problems: []string{"PATH_PREFIX"}},
		{name: "path prefix with a dot-dot segment", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.PathPrefix = "/auth/.." }, problems: []string{"PATH_PREFIX"}},
		{name: "ports out of range", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.Port, configuration.MetricsPort = 0, 65536 }, problems: []string{"PORT 0", "METRICS_PORT 65536"}},
		{name: "same port twice", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.MetricsPort = 8080 }, problems: []string{"PORT and METRICS_PORT must differ"}},
		{name: "sample rate and delays", configuration: validOIDCConfiguration, change: func(configuration *Configuration) {
			configuration.WideEventSampleRate, configuration.ShutdownDelaySeconds = 0, -1
			configuration.SessionMaximumAgeSeconds, configuration.SessionRefreshIntervalSeconds, configuration.JWTLifetimeSeconds = 0, 0, 0
			configuration.SessionRedisDatabase = -1
		}, problems: []string{"WIDE_EVENT_SAMPLE_RATE", "SHUTDOWN_DELAY_SECONDS", "SESSION_MAXIMUM_AGE_SECONDS", "SESSION_REFRESH_INTERVAL_SECONDS", "JWT_LIFETIME_SECONDS", "SESSION_REDIS_DATABASE"}},
		{name: "shutdown delay beyond the grace period", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.ShutdownDelaySeconds = 11 }, problems: []string{"SHUTDOWN_DELAY_SECONDS 11 must be between 0 and 10"}},
		{name: "session key not base64", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.SessionEncryptionKey = "not base64!" }, problems: []string{"SESSION_ENCRYPTION_KEY"}},
		{name: "session key too short", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.SessionEncryptionKey = "c2hvcnQ=" }, problems: []string{"SESSION_ENCRYPTION_KEY"}},
		{name: "unknown same site", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.SessionSameSite = "Lax" }, problems: []string{"SESSION_SAME_SITE \"Lax\""}},
		{name: "strict same site", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.SessionSameSite = "strict" }, problems: []string{"SESSION_SAME_SITE=strict breaks the login"}},
		{name: "same site none with insecure cookie", configuration: validOIDCConfiguration, change: func(configuration *Configuration) {
			configuration.SessionSameSite, configuration.SessionInsecureCookie = "none", true
		}, problems: []string{"SESSION_SAME_SITE=none requires a secure cookie"}},
		{name: "redis without address", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.SessionRedisEnabled = true }, problems: []string{"SESSION_REDIS_ADDRESS"}},
		{name: "oidc without issuer and client", configuration: validOIDCConfiguration, change: func(configuration *Configuration) {
			configuration.OIDCIssuer, configuration.OIDCClientID, configuration.OIDCClientSecret = "", "", " "
		}, problems: []string{"OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"}},
		{name: "unknown claim mapper", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.OIDCClaimMapper = "azure" }, problems: []string{"OIDC_CLAIM_MAPPER"}},
		{name: "github without client and teams", configuration: validGitHubConfiguration, change: func(configuration *Configuration) {
			configuration.GitHubClientID, configuration.GitHubClientSecret, configuration.GitHubAllowedTeams = "", "", nil
		}, problems: []string{"GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "GITHUB_ALLOWED_TEAMS"}},
		{name: "keycloak with github", configuration: validGitHubConfiguration, change: func(configuration *Configuration) {
			configuration.KeycloakEnabled, configuration.KeycloakURL, configuration.KeycloakRealm = true, "https://keycloak.example.com", "company"
			configuration.KeycloakClientID, configuration.KeycloakClientSecret = "forwardauth", "keycloak-secret"
		}, problems: []string{"KEYCLOAK_ENABLED=true requires PROVIDER=oidc"}},
		{name: "keycloak without anything", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.KeycloakEnabled = true }, problems: []string{"KEYCLOAK_URL", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", "KEYCLOAK_CLIENT_SECRET"}},
		{name: "keycloak password grant without credentials", configuration: validOIDCConfiguration, change: func(configuration *Configuration) {
			configuration.KeycloakEnabled, configuration.KeycloakGrantType = true, grantTypePassword
		}, problems: []string{"KEYCLOAK_USERNAME", "KEYCLOAK_PASSWORD"}},
		{name: "unknown keycloak grant", configuration: validOIDCConfiguration, change: func(configuration *Configuration) {
			configuration.KeycloakEnabled, configuration.KeycloakGrantType = true, "implicit"
		}, problems: []string{"KEYCLOAK_GRANT_TYPE \"implicit\""}},
		{name: "jwt without key", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.JWTEnabled = true }, problems: []string{"JWT_PRIVATE_KEY"}},
		{name: "jwt header that is no header name", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.JWTHeader = "X Auth" }, problems: []string{"JWT_HEADER \"X Auth\" is not an HTTP header name"}},
		{name: "jwt header the check answer sets", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.JWTHeader = "Cache-Control" }, problems: []string{"JWT_HEADER \"Cache-Control\" is set by the check answer"}},
		{name: "api key secret too short", configuration: validOIDCConfiguration, change: func(configuration *Configuration) { configuration.APIKeys = []string{"ci:short-secret"} }, problems: []string{"API_KEYS: apikey: key 0: key secret is shorter than 16 bytes"}},
		{name: "api key used twice", configuration: validOIDCConfiguration, change: func(configuration *Configuration) {
			configuration.APIKeys = []string{"ci:" + testSecret, "ci:other-secret-0123456789"}
		}, problems: []string{"API_KEYS: apikey: key 1: name or secret is used by another key"}},
		{name: "problems of several kinds at once", configuration: validOIDCConfiguration, change: func(configuration *Configuration) {
			configuration.PathPrefix, configuration.APIKeys, configuration.JWTHeader = "/auth/:tenant", []string{"ci:short-secret"}, "X Auth"
		}, problems: []string{"PATH_PREFIX", "API_KEYS", "JWT_HEADER"}},
		{name: "permissions for an unknown key", configuration: validOIDCConfiguration, change: func(configuration *Configuration) {
			configuration.APIKeyPermissions = []string{"ci=builds:write"}
		}, problems: []string{"API_KEY_PERMISSIONS names \"ci\""}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configuration := testCase.configuration()
			testCase.change(configuration)

			err := validateConfiguration(configuration)

			require.Error(t, err)
			for _, problem := range testCase.problems {
				require.ErrorContains(t, err, problem)
			}
		})
	}
}

func TestAPIKeysParsesKeysAndTheirPermissions(t *testing.T) {
	keys, err := apiKeys(
		[]string{"ci:" + testSecret, "reader:reader-secret-0123456789", "colon:secret:with:colons-0123"},
		[]string{"ci=builds:write+*:read", "reader=*:read"},
	)

	require.NoError(t, err)
	require.Equal(t, []apikey.Key{
		{Name: "ci", Secret: testSecret, Permissions: []auth.Permission{{Resource: "builds", Access: auth.AccessWrite}, {Resource: auth.AllResources, Access: auth.AccessRead}}},
		{Name: "reader", Secret: "reader-secret-0123456789", Permissions: []auth.Permission{{Resource: auth.AllResources, Access: auth.AccessRead}}},
		{Name: "colon", Secret: "secret:with:colons-0123"},
	}, keys)
	_, err = apikey.New(&apikey.Options{Keys: keys})
	require.NoError(t, err, "the parsed keys are valid apikey keys")
}

func TestAPIKeysRefusesMalformedEntriesWithoutRepeatingSecrets(t *testing.T) {
	testCases := []struct {
		name        string
		keys        []string
		permissions []string
		problem     string
	}{
		{name: "entry without name separator", keys: []string{testSecret}, problem: "API_KEYS entry 1 must be name:secret"},
		{name: "entry with empty name", keys: []string{":" + testSecret}, problem: "API_KEYS entry 1 must be name:secret"},
		{name: "permissions without separator", keys: []string{"ci:" + testSecret}, permissions: []string{"ci"}, problem: "must be name=permission"},
		{name: "permissions with empty name", keys: []string{"ci:" + testSecret}, permissions: []string{"=builds:read"}, problem: "must be name=permission"},
		{name: "permissions twice", keys: []string{"ci:" + testSecret}, permissions: []string{"ci=builds:read", "ci=builds:write"}, problem: "names \"ci\" more than once"},
		{name: "no permission", keys: []string{"ci:" + testSecret}, permissions: []string{"ci="}, problem: "has no permission"},
		{name: "unparsable permission", keys: []string{"ci:" + testSecret}, permissions: []string{"ci=builds:write+Deploy:read"}, problem: "entry for \"ci\""},
		{name: "unknown access", keys: []string{"ci:" + testSecret}, permissions: []string{"ci=builds:admin"}, problem: "entry for \"ci\""},
		{name: "unknown key", keys: []string{"ci:" + testSecret}, permissions: []string{"deploy=builds:read"}, problem: "names \"deploy\", which is no key"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			keys, err := apiKeys(testCase.keys, testCase.permissions)

			require.ErrorContains(t, err, testCase.problem)
			require.NotContains(t, err.Error(), testSecret)
			require.Nil(t, keys)
		})
	}
}

func TestSameSiteMode(t *testing.T) {
	testCases := []struct {
		value string
		want  http.SameSite
	}{
		{value: "lax", want: http.SameSiteLaxMode},
		{value: "none", want: http.SameSiteNoneMode},
	}
	for _, testCase := range testCases {
		t.Run(testCase.value, func(t *testing.T) {
			got, err := sameSiteMode(testCase.value)

			require.NoError(t, err)
			require.Equal(t, testCase.want, got)
		})
	}
	for _, value := range []string{strings.ToUpper("lax"), "strict"} {
		_, err := sameSiteMode(value)
		require.Error(t, err, value)
	}
}
