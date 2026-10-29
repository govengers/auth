package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

func TestUsernamePattern(t *testing.T) {
	testCases := []struct {
		username string
		valid    bool
	}{
		{username: "abc", valid: true},
		{username: "user123", valid: true},
		{username: "test_user", valid: true},
		{username: "User_123", valid: true},
		{username: strings.Repeat("a", 50), valid: true},
		{username: "ab"},
		{username: ""},
		{username: strings.Repeat("a", 51)},
		{username: "user name"},
		{username: "user-name"},
		{username: "user.name"},
		{username: "user@name"},
		{username: "üser"},
		{username: "user\n"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.username, func(t *testing.T) {
			require.Equal(t, testCase.valid, usernamePattern.MatchString(testCase.username))
		})
	}
}

func TestEmailPattern(t *testing.T) {
	testCases := []struct {
		email string
		valid bool
	}{
		{email: "test@example.com", valid: true},
		{email: "user.name@example.com", valid: true},
		{email: "user+tag@example.co.uk", valid: true},
		{email: "123@example.com", valid: true},
		{email: "test_user@example-domain.com", valid: true},
		{email: ""},
		{email: "notanemail"},
		{email: "@example.com"},
		{email: "user@"},
		{email: "user @example.com"},
		{email: "user@example"},
		{email: "user@@example.com"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.email, func(t *testing.T) {
			require.Equal(t, testCase.valid, emailPattern.MatchString(testCase.email))
		})
	}
}

func TestPolicyCheck(t *testing.T) {
	everything := Policy{MinimumLength: 8, RequireUppercase: true, RequireLowercase: true, RequireDigit: true, RequireSpecial: true}
	testCases := []struct {
		name     string
		policy   Policy
		password string
		valid    bool
	}{
		{name: "long enough", policy: Policy{MinimumLength: 12}, password: "abcdefghijkl", valid: true},
		{name: "too short", policy: Policy{MinimumLength: 12}, password: "abcdefghijk"},
		{name: "length counts characters, not bytes", policy: Policy{MinimumLength: 4}, password: "äöüß", valid: true},
		{name: "multi-byte characters below the minimum", policy: Policy{MinimumLength: 5}, password: "äöüß"},
		{name: "128 bytes", policy: Policy{MinimumLength: 1}, password: strings.Repeat("a", 128), valid: true},
		{name: "129 bytes", policy: Policy{MinimumLength: 1}, password: strings.Repeat("a", 129)},
		{name: "all rules met", policy: everything, password: "Abcdef1!", valid: true},
		{name: "unicode letters and a symbol count", policy: everything, password: "Ärger1€x", valid: true},
		{name: "no upper-case letter", policy: everything, password: "abcdef1!"},
		{name: "no lower-case letter", policy: everything, password: "ABCDEF1!"},
		{name: "no digit", policy: everything, password: "Abcdefg!"},
		{name: "no special character", policy: everything, password: "Abcdefg1"},
		{name: "a space is special", policy: Policy{MinimumLength: 3, RequireSpecial: true}, password: "a b", valid: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.policy.check(testCase.password)
			if testCase.valid {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestValidateRegistration(t *testing.T) {
	username, email := "ada", "ada@example.com"
	badUsername, badEmail := "a", "ada@example"
	defaults := Options{Policy: Policy{MinimumLength: 12}}
	testCases := []struct {
		name         string
		registration registerRequest
		options      Options
		wantCode     string // "" with wantKind nil: valid
		wantKind     error
	}{
		{name: "username", registration: registerRequest{Username: &username, Password: testPassword}, options: defaults},
		{name: "email", registration: registerRequest{Email: &email, Password: testPassword}, options: defaults},
		{name: "both", registration: registerRequest{Username: &username, Email: &email, Password: testPassword}, options: defaults},
		{name: "neither", registration: registerRequest{Password: testPassword}, options: defaults, wantKind: auth.ErrInvalidRequest},
		{
			name: "username while username login is disabled", registration: registerRequest{Username: &username, Email: &email, Password: testPassword},
			options: Options{Policy: defaults.Policy, DisableUsernameLogin: true}, wantKind: auth.ErrInvalidRequest,
		},
		{
			name: "email while email login is disabled", registration: registerRequest{Username: &username, Email: &email, Password: testPassword},
			options: Options{Policy: defaults.Policy, DisableEmailLogin: true}, wantKind: auth.ErrInvalidRequest,
		},
		{name: "invalid username", registration: registerRequest{Username: &badUsername, Password: testPassword}, options: defaults, wantKind: auth.ErrInvalidRequest, wantCode: "invalid_username"},
		{name: "invalid email", registration: registerRequest{Email: &badEmail, Password: testPassword}, options: defaults, wantKind: auth.ErrInvalidRequest, wantCode: "invalid_email"},
		{name: "weak password", registration: registerRequest{Username: &username, Password: "short"}, options: defaults, wantKind: auth.ErrInvalidRequest, wantCode: "weak_password"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateRegistration(testCase.registration, testCase.options)
			if testCase.wantKind == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, testCase.wantKind)
			var refusal *auth.Error
			require.True(t, errors.As(err, &refusal))
			require.Equal(t, testCase.wantCode, refusal.Code)
		})
	}
}

func TestKindOf(t *testing.T) {
	require.Equal(t, identifierUsername, kindOf("ada"))
	require.Equal(t, identifierEmail, kindOf("ada@example.com"))
	require.Equal(t, identifierEmail, kindOf("@"))
	require.Equal(t, identifierUsername, kindOf(""))
}
