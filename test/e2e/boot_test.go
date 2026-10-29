//go:build e2e

package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// oidcEnvironment is a complete OIDC configuration except the issuer it talks to.
func oidcEnvironment(issuer string) map[string]string {
	return map[string]string{
		"PROVIDER":                "oidc",
		"EXTERNAL_URL":            "http://127.0.0.1:8080",
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
			name: "permissions for a key that does not exist",
			environment: merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{
				"API_KEYS": "ci:ci-secret-0123456789", "API_KEY_PERMISSIONS": "deploy=builds:write",
			}),
			problems: []string{`API_KEY_PERMISSIONS names \"deploy\", which is no key in API_KEYS`},
		},
		{
			name: "unparsable permission",
			environment: merged(oidcEnvironment("http://127.0.0.1:1"), map[string]string{
				"API_KEYS": "ci:ci-secret-0123456789", "API_KEY_PERMISSIONS": "ci=Builds:write",
			}),
			problems: []string{`API_KEY_PERMISSIONS entry for \"ci\"`},
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
