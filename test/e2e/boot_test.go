//go:build e2e

package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// oidcEnvironment is a complete OIDC configuration against issuer, except EXTERNAL_URL, which start sets.
func oidcEnvironment(issuer string) map[string]string {
	return map[string]string{
		"PROVIDER":                "oidc",
		"SESSION_ENCRYPTION_KEY":  testEncryptionKey,
		"SESSION_INSECURE_COOKIE": "true",
		"SHUTDOWN_DELAY_SECONDS":  "0",
		"OIDC_ISSUER":             issuer,
		"OIDC_CLIENT_ID":          "forwardauth",
		"OIDC_CLIENT_SECRET":      "e2e-oidc-secret",
	}
}

func TestBootFailsListingEveryMissingOrInvalidVariable(t *testing.T) {
	testCases := []struct {
		name        string
		environment map[string]string
		problems    []string
	}{
		{
			name:        "nothing set",
			environment: map[string]string{},
			problems:    []string{"PROVIDER is not set", "EXTERNAL_URL is not set", "SESSION_ENCRYPTION_KEY is not set"},
		},
		{
			name: "github without allowed teams",
			environment: map[string]string{
				"PROVIDER": "github", "EXTERNAL_URL": "http://127.0.0.1:8080", "SESSION_ENCRYPTION_KEY": testEncryptionKey,
				"GITHUB_CLIENT_ID": "client", "GITHUB_CLIENT_SECRET": "secret",
			},
			problems: []string{"GITHUB_ALLOWED_TEAMS"},
		},
		{
			name:        "api keys enabled without keys",
			environment: merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{"EXTERNAL_URL": "http://127.0.0.1:8080", "API_KEYS_ENABLED": "true"}),
			problems:    []string{"API_KEYS needs at least one name:secret when API_KEYS_ENABLED=true"},
		},
		{
			name: "permissions for a key that does not exist",
			environment: merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{
				"EXTERNAL_URL": "http://127.0.0.1:8080", "API_KEYS_ENABLED": "true", "API_KEYS": "ci:ci-secret-0123456789", "API_KEY_PERMISSIONS": "deploy=builds:write",
			}),
			problems: []string{`API_KEY_PERMISSIONS names \"deploy\", which is no key in API_KEYS`},
		},
		{
			name: "unparsable permission",
			environment: merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{
				"EXTERNAL_URL": "http://127.0.0.1:8080", "API_KEYS_ENABLED": "true", "API_KEYS": "ci:ci-secret-0123456789", "API_KEY_PERMISSIONS": "ci=Builds:write",
			}),
			problems: []string{`API_KEY_PERMISSIONS entry for \"ci\"`},
		},
		{
			name: "every problem at once, also those the components judge",
			environment: merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{
				"EXTERNAL_URL": "http://127.0.0.1:8080", "PATH_PREFIX": "/auth/:tenant", "API_KEYS_ENABLED": "true", "API_KEYS": "ci:ci-secret-0123456789,deploy:ci-secret-0123456789",
			}),
			problems: []string{"PATH_PREFIX", "API_KEYS: apikey: key 2: name or secret is used by another key"},
		},
		{
			name: "redis that does not answer",
			environment: merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{
				"EXTERNAL_URL": "http://127.0.0.1:8080", "SESSION_REDIS_ENABLED": "true", "SESSION_REDIS_ADDRESS": "127.0.0.1:1",
			}),
			problems: []string{"SESSION_REDIS_ADDRESS: ping Redis at 127.0.0.1:1"},
		},
		{
			name: "redis sentinel and tls values that do not fit, and a trusted proxy that is no address",
			environment: merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{
				"EXTERNAL_URL": "http://127.0.0.1:8080", "SESSION_REDIS_ENABLED": "true", "SESSION_REDIS_ADDRESS": "127.0.0.1:6379",
				"SESSION_REDIS_SENTINEL_MASTER": "sessions", "SESSION_REDIS_SENTINEL_PASSWORD": "ci-secret-0123456789",
				"SESSION_REDIS_TLS_CA_FILE": "/does/not/exist.pem", "TRUSTED_PROXIES": "10.0.0.0/8,traefik",
			}),
			problems: []string{
				"SESSION_REDIS_ADDRESS must be empty with SESSION_REDIS_SENTINEL_MASTER", "SESSION_REDIS_SENTINEL_ADDRESSES needs at least one host:port",
				"SESSION_REDIS_TLS_CA_FILE is set but SESSION_REDIS_TLS_ENABLED=false", `TRUSTED_PROXIES: \"traefik\" is neither an IP address nor a CIDR`,
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			exitCode, output := runToExit(t, testCase.environment)

			require.NotZero(t, exitCode, output)
			for _, problem := range testCase.problems {
				require.Contains(t, output, problem)
			}
			require.NotContains(t, output, "ci-secret-0123456789", "secrets never reach the log")
		})
	}
}

// merged returns base with the entries of changes added or replaced.
func merged(base, changes map[string]string) map[string]string {
	result := make(map[string]string, len(base)+len(changes))
	for key, value := range base {
		result[key] = value
	}
	for key, value := range changes {
		result[key] = value
	}
	return result
}
