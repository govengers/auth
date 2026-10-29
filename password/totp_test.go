package password

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

const (
	verifyPath  = "/auth/password/totp/verify"
	statusPath  = "/auth/password/totp"
	setupPath   = "/auth/password/totp/setup"
	enablePath  = "/auth/password/totp/enable"
	disablePath = "/auth/password/totp/disable"
)

func TestChallengeFor(t *testing.T) {
	enrolled := &User{TOTPEnabled: true}
	unenrolled := &User{}
	testCases := []struct {
		name          string
		totp          TOTPOptions
		user          *User
		wantChallenge Challenge
		wantPending   bool
	}{
		{name: "TOTP disabled", totp: TOTPOptions{Required: true}, user: enrolled},
		{name: "enrolled user", totp: TOTPOptions{Enabled: true}, user: enrolled, wantChallenge: ChallengeTOTP, wantPending: true},
		{name: "unenrolled user", totp: TOTPOptions{Enabled: true}, user: unenrolled},
		{name: "unenrolled user, TOTP required", totp: TOTPOptions{Enabled: true, Required: true}, user: unenrolled, wantChallenge: ChallengeTOTPSetup, wantPending: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := &Provider{options: Options{TOTP: testCase.totp}}
			challenge, pending := provider.challengeFor(testCase.user)
			require.Equal(t, testCase.wantChallenge, challenge)
			require.Equal(t, testCase.wantPending, pending)
		})
	}
}

func TestAccountName(t *testing.T) {
	id := uuid.New()
	require.Equal(t, "ada", accountName(&User{ID: id, Username: new("ada"), Email: new("ada@example.com")}))
	require.Equal(t, "ada@example.com", accountName(&User{ID: id, Username: new(""), Email: new("ada@example.com")}))
	require.Equal(t, id.String(), accountName(&User{ID: id}))
}

// pendingClient logs in a user with TOTP and returns the client holding the pending login.
func (f *fixture) pendingClient(t *testing.T, username string) *client {
	t.Helper()
	browser := f.newClient(t)
	recorder := browser.login(username)
	require.Equal(t, http.StatusAccepted, recorder.Code, recorder.Body.String())
	f.outcomes.take()
	return browser
}

func TestLoginChallengesTOTPUsers(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user, _ := fixture.createTOTPUser(t, "ada")
	browser := fixture.newClient(t)

	recorder := browser.login("ada")

	require.Equal(t, http.StatusAccepted, recorder.Code)
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.JSONEq(t, `{"challenge":"totp"}`, recorder.Body.String())
	require.True(t, browser.hasSession())
	_, err := fixture.sessionIdentity(t, browser)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.ResultChallenge, outcome.Result)
	require.Equal(t, user.ID, outcome.Identity.UserID)
	requireRefusal(t, browser.get(statusPath), http.StatusUnauthorized, "unauthenticated")
}

func TestLoginFailsForEnrolledUsersWhileTOTPIsOff(t *testing.T) {
	fixture := newFixture(t, Options{})
	user := fixture.createUser(t, "ada", "")
	requireSetTOTP(t, fixture.storage, user.ID, testSecret, nil)
	browser := fixture.newClient(t)

	recorder := browser.login("ada")

	requireRefusal(t, recorder, http.StatusInternalServerError, "internal")
	require.False(t, browser.hasSession())
	require.Equal(t, auth.ResultError, fixture.outcomes.last(t).Result)
}

func TestVerifyTOTP(t *testing.T) {
	testCases := []struct {
		name       string
		options    Options
		code       func(t *testing.T, fixture *fixture, backupCodes []string) string
		backupCode bool
		wantStatus int
	}{
		{name: "current code", code: func(t *testing.T, fixture *fixture, _ []string) string { return fixture.code(t, testSecret, 0) }, wantStatus: http.StatusOK},
		{name: "code with spaces around", code: func(t *testing.T, fixture *fixture, _ []string) string {
			return " " + fixture.code(t, testSecret, 0) + " "
		}, wantStatus: http.StatusOK},
		{name: "previous period", code: func(t *testing.T, fixture *fixture, _ []string) string {
			return fixture.code(t, testSecret, -30*time.Second)
		}, wantStatus: http.StatusOK},
		{name: "next period", code: func(t *testing.T, fixture *fixture, _ []string) string {
			return fixture.code(t, testSecret, 30*time.Second)
		}, wantStatus: http.StatusOK},
		{name: "two periods back", code: func(t *testing.T, fixture *fixture, _ []string) string {
			return fixture.code(t, testSecret, -60*time.Second)
		}, wantStatus: http.StatusUnauthorized},
		{name: "two periods ahead", code: func(t *testing.T, fixture *fixture, _ []string) string {
			return fixture.code(t, testSecret, 60*time.Second)
		}, wantStatus: http.StatusUnauthorized},
		{
			name: "wider skew", options: Options{TOTP: TOTPOptions{Enabled: true, Issuer: "Example", Skew: 2}},
			code: func(t *testing.T, fixture *fixture, _ []string) string {
				return fixture.code(t, testSecret, -60*time.Second)
			}, wantStatus: http.StatusOK,
		},
		{name: "wrong code", code: func(*testing.T, *fixture, []string) string { return "000000" }, wantStatus: http.StatusUnauthorized},
		{name: "backup code", code: func(_ *testing.T, _ *fixture, backupCodes []string) string { return backupCodes[1] }, backupCode: true, wantStatus: http.StatusOK},
		{name: "backup code without the flag", code: func(_ *testing.T, _ *fixture, backupCodes []string) string { return backupCodes[1] }, wantStatus: http.StatusUnauthorized},
		{name: "TOTP code flagged as backup code", code: func(t *testing.T, fixture *fixture, _ []string) string { return fixture.code(t, testSecret, 0) }, backupCode: true, wantStatus: http.StatusUnauthorized},
		{
			name: "backup code while backup codes are disabled", options: Options{TOTP: TOTPOptions{Enabled: true, Issuer: "Example", DisableBackupCodes: true}},
			code: func(_ *testing.T, _ *fixture, backupCodes []string) string { return backupCodes[1] }, backupCode: true, wantStatus: http.StatusUnauthorized,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := testCase.options
			if !options.TOTP.Enabled {
				options = totpOptions()
			}
			fixture := newFixture(t, options)
			user, backupCodes := fixture.createTOTPUser(t, "ada")
			browser := fixture.pendingClient(t, "ada")

			recorder := browser.post(verifyPath, map[string]any{"code": testCase.code(t, fixture, backupCodes), "backupCode": testCase.backupCode})

			outcome := fixture.outcomes.last(t)
			require.Equal(t, auth.ActionTOTPVerify, outcome.Action)
			if testCase.wantStatus != http.StatusOK {
				requireRefusal(t, recorder, testCase.wantStatus, "invalid_totp_code")
				require.Equal(t, auth.ResultDenied, outcome.Result)
				require.Len(t, fixture.storedUser(t, user.ID).BackupCodeHashes, 3)
				return
			}
			requireIdentity(t, recorder, http.StatusOK, user)
			require.Equal(t, auth.ResultSuccess, outcome.Result)
			identity, err := fixture.sessionIdentity(t, browser)
			require.NoError(t, err)
			require.Equal(t, user.ID, identity.UserID)
		})
	}
}

func TestTOTPUsesTheConfiguredPeriodAndDigits(t *testing.T) {
	options := totpOptions()
	options.TOTP.Period, options.TOTP.Digits = 60, 8
	fixture := newFixture(t, options)
	user := fixture.createUser(t, "ada", "")
	browser := loggedInClient(t, fixture)

	setup := decodeBody[setupResponse](t, browser.post(setupPath, map[string]any{}))
	require.Contains(t, setup.OTPAuthURL, "digits=8")
	require.Contains(t, setup.OTPAuthURL, "period=60")
	enable := browser.post(enablePath, map[string]any{"code": fixture.code(t, setup.Secret, 0), "password": testPassword})
	require.Equal(t, http.StatusOK, enable.Code, enable.Body.String())

	pending := fixture.pendingClient(t, "ada")
	fixture.clock.advance(time.Minute) // the enable code used the current step
	sixDigits, err := totp.GenerateCodeCustom(setup.Secret, fixture.clock.now(), totp.ValidateOpts{Period: 60, Digits: otp.DigitsSix})
	require.NoError(t, err)
	requireRefusal(t, pending.post(verifyPath, map[string]any{"code": sixDigits}), http.StatusUnauthorized, "invalid_totp_code")
	requireIdentity(t, pending.post(verifyPath, map[string]any{"code": fixture.code(t, setup.Secret, 0)}), http.StatusOK, user)
}

func TestVerifyFailsOnAnUndecodableSecret(t *testing.T) {
	const undecodable = "not base32!"
	fixture := newFixture(t, totpOptions())
	user := fixture.createUser(t, "ada", "")
	requireSetTOTP(t, fixture.storage, user.ID, undecodable, nil)
	browser := fixture.pendingClient(t, "ada")

	recorder := browser.post(verifyPath, map[string]any{"code": "123456"})

	requireRefusal(t, recorder, http.StatusInternalServerError, "internal")
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.ResultError, outcome.Result)
	require.ErrorContains(t, outcome.Err, user.ID.String())
	require.NotContains(t, outcome.Err.Error(), undecodable, "errors never carry the secret")

	recorder = browser.post(verifyPath, map[string]any{"code": "12345"})

	requireRefusal(t, recorder, http.StatusUnauthorized, "invalid_totp_code") // a code of the wrong length is just wrong
}

func TestTOTPCodeIsSingleUse(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	fixture.createTOTPUser(t, "ada")
	code := fixture.code(t, testSecret, 0)
	require.Equal(t, http.StatusOK, fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": code}).Code)

	requireRefusal(t, fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": code}), http.StatusUnauthorized, "invalid_totp_code")
	previous := fixture.code(t, testSecret, -30*time.Second)
	requireRefusal(t, fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": previous}), http.StatusUnauthorized, "invalid_totp_code")
	next := fixture.code(t, testSecret, 30*time.Second)
	require.Equal(t, http.StatusOK, fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": next}).Code)
}

func TestCodeIsSingleUseUnderRace(t *testing.T) {
	testCases := []struct {
		name string
		body func(t *testing.T, fixture *fixture, backupCodes []string) map[string]any
	}{
		{name: "TOTP code", body: func(t *testing.T, fixture *fixture, _ []string) map[string]any {
			return map[string]any{"code": fixture.code(t, testSecret, 0)}
		}},
		{name: "backup code", body: func(_ *testing.T, _ *fixture, backupCodes []string) map[string]any {
			return map[string]any{"code": backupCodes[0], "backupCode": true}
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFixture(t, totpOptions())
			_, backupCodes := fixture.createTOTPUser(t, "ada")
			body := testCase.body(t, fixture, backupCodes)
			browsers := []*client{fixture.pendingClient(t, "ada"), fixture.pendingClient(t, "ada"), fixture.pendingClient(t, "ada")}

			statuses := make([]int, len(browsers))
			var waitGroup sync.WaitGroup
			for index, browser := range browsers {
				request := browser.postRequest(verifyPath, body)
				waitGroup.Go(func() {
					statuses[index] = browser.postStatus(request)
				})
			}
			waitGroup.Wait()

			require.ElementsMatch(t, []int{http.StatusOK, http.StatusUnauthorized, http.StatusUnauthorized}, statuses)
		})
	}
}

func TestEnableCodeIsSingleUse(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	fixture.createUser(t, "ada", "")
	secret, _ := enroll(t, fixture, loggedInClient(t, fixture))

	recorder := fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": fixture.code(t, secret, 0)})

	requireRefusal(t, recorder, http.StatusUnauthorized, "invalid_totp_code")
	recorder = fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": fixture.code(t, secret, 30*time.Second)})
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestBackupCodeIsSingleUse(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user, backupCodes := fixture.createTOTPUser(t, "ada")

	recorder := fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": strings.ToUpper(" " + backupCodes[0] + " "), "backupCode": true})
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Len(t, fixture.storedUser(t, user.ID).BackupCodeHashes, 2)

	recorder = fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": backupCodes[0], "backupCode": true})
	requireRefusal(t, recorder, http.StatusUnauthorized, "invalid_totp_code")

	recorder = fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": backupCodes[2], "backupCode": true})
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Len(t, fixture.storedUser(t, user.ID).BackupCodeHashes, 1)
}

func TestVerifyEndsThePendingLoginAfterTheLastAttempt(t *testing.T) {
	options := totpOptions()
	options.TOTP.MaximumAttempts = 2
	fixture := newFixture(t, options)
	fixture.createTOTPUser(t, "ada")
	browser := fixture.pendingClient(t, "ada")

	requireRefusal(t, browser.post(verifyPath, map[string]any{"code": "000000"}), http.StatusUnauthorized, "invalid_totp_code")
	require.True(t, browser.hasSession())
	requireRefusal(t, browser.post(verifyPath, map[string]any{"code": "000000"}), http.StatusUnauthorized, "invalid_totp_code")
	require.False(t, browser.hasSession())
	fixture.outcomes.take()

	recorder := browser.post(verifyPath, map[string]any{"code": fixture.code(t, testSecret, 0)})

	requireRefusal(t, recorder, http.StatusUnauthorized, "no_pending_login")
}

func TestPendingLoginsShareTheAttemptBudget(t *testing.T) {
	options := totpOptions()
	options.TOTP.MaximumAttempts = 1
	fixture := newFixture(t, options)
	fixture.createTOTPUser(t, "ada")
	first := fixture.pendingClient(t, "ada")
	second := fixture.pendingClient(t, "ada")
	requireRefusal(t, first.post(verifyPath, map[string]any{"code": "000000"}), http.StatusUnauthorized, "invalid_totp_code")
	fixture.outcomes.take()

	recorder := second.post(verifyPath, map[string]any{"code": fixture.code(t, testSecret, 0)})

	requireRefusal(t, recorder, http.StatusUnauthorized, "invalid_totp_code")
	require.False(t, second.hasSession())
	var refusal *auth.Error
	require.ErrorAs(t, fixture.outcomes.last(t).Err, &refusal)
	require.Equal(t, "attempts exhausted", refusal.Reason)
}

func TestFailedAttemptsOutliveTheLogin(t *testing.T) {
	options := totpOptions()
	options.TOTP.MaximumAttempts = 2
	fixture := newFixture(t, options)
	user, _ := fixture.createTOTPUser(t, "ada")
	requireRefusal(t, fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": "000000"}), http.StatusUnauthorized, "invalid_totp_code")
	requireRefusal(t, fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": "000000"}), http.StatusUnauthorized, "invalid_totp_code")
	browser := fixture.pendingClient(t, "ada")

	recorder := browser.post(verifyPath, map[string]any{"code": fixture.code(t, testSecret, 0)})

	requireRefusal(t, recorder, http.StatusUnauthorized, "invalid_totp_code")
	var refusal *auth.Error
	require.ErrorAs(t, fixture.outcomes.last(t).Err, &refusal)
	require.Equal(t, "attempts exhausted", refusal.Reason)

	require.NoError(t, fixture.storage.ResetTOTPAttempts(t.Context(), user.ID))
	recorder = fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": fixture.code(t, testSecret, 0)})
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestVerifyRefusesWithoutAPendingLogin(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user, _ := fixture.createTOTPUser(t, "ada")
	expired := fixture.pendingClient(t, "ada")
	replayed := fixture.pendingClient(t, "ada")
	stolen := replayed.copy()
	require.Equal(t, http.StatusOK, replayed.post(verifyPath, map[string]any{"code": fixture.code(t, testSecret, 0)}).Code)
	cleared := fixture.pendingClient(t, "ada")
	fixture.clock.advance(5*time.Minute + time.Second)
	enrollmentOptions := totpOptions()
	enrollmentOptions.TOTP.Required = true
	enrolling := newFixture(t, enrollmentOptions)
	enrolling.createUser(t, "grace", "")
	enrollingBrowser := enrolling.newClient(t)
	require.Equal(t, http.StatusAccepted, enrollingBrowser.login("grace").Code)

	// The clients belong to this test, so the cases run in it rather than in subtests.
	browsers := map[string]*client{
		"no session":            fixture.newClient(t),
		"full session":          replayed,
		"expired pending login": expired,
		"pending login revoked by the successful verification": stolen,
		"pending enrollment": enrollingBrowser,
	}
	for name, browser := range browsers {
		recorder := browser.post(verifyPath, map[string]any{"code": "000000"})
		require.Equal(t, http.StatusUnauthorized, recorder.Code, name)
		require.Equal(t, "no_pending_login", decodeBody[auth.ErrorResponse](t, recorder).Code, name)
	}

	fixture.clock.advance(-5*time.Minute - time.Second)
	require.NoError(t, fixture.storage.ClearTOTP(t.Context(), user.ID))
	recorder := cleared.post(verifyPath, map[string]any{"code": fixture.code(t, testSecret, 0)})
	requireRefusal(t, recorder, http.StatusUnauthorized, "no_pending_login")
	require.False(t, cleared.hasSession())
}

func TestVerifyStorageFailures(t *testing.T) {
	testCases := []struct {
		operation  string
		backupCode bool
	}{
		{operation: "GetUserByID", backupCode: true},
		{operation: "ConsumeTOTPAttempt", backupCode: true},
		{operation: "ConsumeBackupCode", backupCode: true},
		{operation: "ConsumeTOTPStep"},
		{operation: "ResetTOTPAttempts", backupCode: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.operation, func(t *testing.T) {
			fixture := newFixture(t, totpOptions())
			_, backupCodes := fixture.createTOTPUser(t, "ada")
			browser := fixture.pendingClient(t, "ada")
			fixture.failStorage(testCase.operation)
			code := fixture.code(t, testSecret, 0)
			if testCase.backupCode {
				code = backupCodes[0]
			}

			recorder := browser.post(verifyPath, map[string]any{"code": code, "backupCode": testCase.backupCode})

			requireRefusal(t, recorder, http.StatusInternalServerError, "internal")
			require.ErrorIs(t, fixture.outcomes.last(t).Err, errStorageDown)
		})
	}
}

// enroll runs setup and enable on browser and returns the secret and the backup codes.
func enroll(t *testing.T, fixture *fixture, browser *client) (string, []string) {
	t.Helper()
	setup := browser.post(setupPath, map[string]any{})
	require.Equal(t, http.StatusOK, setup.Code, setup.Body.String())
	secret := decodeBody[setupResponse](t, setup).Secret
	enable := browser.post(enablePath, map[string]any{"code": fixture.code(t, secret, 0), "password": testPassword})
	require.Equal(t, http.StatusOK, enable.Code, enable.Body.String())
	return secret, decodeBody[enableResponse](t, enable).BackupCodes
}

func TestRequiredTOTPEnrollsDuringLogin(t *testing.T) {
	options := totpOptions()
	options.TOTP.Required = true
	fixture := newFixture(t, options)
	user := fixture.createUser(t, "ada", "")
	browser := fixture.newClient(t)

	recorder := browser.login("ada")
	require.Equal(t, http.StatusAccepted, recorder.Code)
	require.JSONEq(t, `{"challenge":"totp_setup"}`, recorder.Body.String())
	requireRefusal(t, browser.get(statusPath), http.StatusUnauthorized, "unauthenticated")
	pending := browser.copy()
	fixture.outcomes.take()

	secret, backupCodes := enroll(t, fixture, browser)

	require.Len(t, backupCodes, 10)
	outcomes := fixture.outcomes.take()
	require.Len(t, outcomes, 2)
	require.Equal(t, auth.ActionTOTPSetup, outcomes[0].Action)
	require.Equal(t, auth.ActionTOTPEnable, outcomes[1].Action)
	require.Equal(t, auth.ResultSuccess, outcomes[1].Result)
	identity, err := fixture.sessionIdentity(t, browser)
	require.NoError(t, err)
	require.Equal(t, user.ID, identity.UserID)
	require.JSONEq(t, `{"enabled":true}`, browser.get(statusPath).Body.String())
	stored := fixture.storedUser(t, user.ID)
	require.True(t, stored.TOTPEnabled)
	require.Equal(t, secret, *stored.TOTPSecret)
	requireRefusal(t, pending.post(setupPath, map[string]any{}), http.StatusUnauthorized, "unauthenticated")

	recorder = fixture.newClient(t).login("ada")
	require.JSONEq(t, `{"challenge":"totp"}`, recorder.Body.String())
}

func TestTOTPManagement(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user := fixture.createUser(t, "ada", "ada@example.com")
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusOK, browser.login("ada").Code)
	before, err := fixture.sessionIdentity(t, browser)
	require.NoError(t, err)

	fixture.outcomes.take()
	require.JSONEq(t, `{"enabled":false}`, browser.get(statusPath).Body.String())
	require.Equal(t, auth.Outcome{Provider: "password", Action: auth.ActionTOTPStatus, Result: auth.ResultSuccess, Identity: before}, fixture.outcomes.last(t))
	requireRefusal(t, browser.post(enablePath, map[string]any{"code": "000000", "password": testPassword}), http.StatusBadRequest, "totp_setup_missing")

	setup := browser.post(setupPath, map[string]any{})
	require.Equal(t, http.StatusOK, setup.Code)
	response := decodeBody[setupResponse](t, setup)
	require.Equal(t, "Example", response.Issuer)
	require.Equal(t, "ada", response.AccountName)
	require.Contains(t, response.OTPAuthURL, "otpauth://totp/Example:ada?")
	require.Contains(t, response.OTPAuthURL, "secret="+response.Secret)

	requireRefusal(t, browser.post(enablePath, map[string]any{"code": fixture.code(t, response.Secret, 0), "password": "wrong password"}), http.StatusUnauthorized, "invalid_credentials")
	requireRefusal(t, browser.post(enablePath, map[string]any{"code": "000000", "password": testPassword}), http.StatusUnauthorized, "invalid_totp_code")

	enable := browser.post(enablePath, map[string]any{"code": fixture.code(t, response.Secret, 0), "password": testPassword})
	require.Equal(t, http.StatusOK, enable.Code, "a mistyped code keeps the scanned secret: %s", enable.Body.String())
	secret, backupCodes := response.Secret, decodeBody[enableResponse](t, enable).BackupCodes
	require.Equal(t, secret, *fixture.storedUser(t, user.ID).TOTPSecret)
	require.Len(t, backupCodes, 10)
	for _, code := range backupCodes {
		require.Len(t, code, 10)
		require.Empty(t, strings.Trim(code, "0123456789"), code)
	}
	after, err := fixture.sessionIdentity(t, browser)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.JSONEq(t, `{"enabled":true}`, browser.get(statusPath).Body.String())
	requireRefusal(t, browser.post(setupPath, map[string]any{}), http.StatusConflict, "totp_already_enabled")
	requireRefusal(t, browser.post(enablePath, map[string]any{"code": fixture.code(t, secret, 0), "password": testPassword}), http.StatusConflict, "totp_already_enabled")

	requireRefusal(t, browser.post(disablePath, map[string]any{"password": "wrong password"}), http.StatusUnauthorized, "invalid_credentials")
	fixture.outcomes.take()
	recorder := browser.post(disablePath, map[string]any{"password": testPassword})
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, auth.Outcome{Provider: "password", Action: auth.ActionTOTPDisable, Result: auth.ResultSuccess, Identity: after}, fixture.outcomes.last(t))
	require.False(t, fixture.storedUser(t, user.ID).TOTPEnabled)
	requireRefusal(t, browser.post(disablePath, map[string]any{"password": testPassword}), http.StatusConflict, "totp_not_enabled")
	requireRefusal(t, browser.post(enablePath, map[string]any{"code": fixture.code(t, secret, 30*time.Second), "password": testPassword}), http.StatusBadRequest, "totp_setup_missing")
}

func TestDisableReportsAFailedSetupDrop(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user := fixture.createUser(t, "ada", "")
	browser := loggedInClient(t, fixture)
	enroll(t, fixture, browser)
	fixture.failSessions(t, "Pop")
	fixture.outcomes.take()

	recorder := browser.post(disablePath, map[string]any{"password": testPassword})

	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.False(t, fixture.storedUser(t, user.ID).TOTPEnabled)
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.ResultSuccess, outcome.Result)
	require.ErrorIs(t, outcome.Err, errStorageDown)
	require.ErrorContains(t, outcome.Err, "drop TOTP setup of user")
}

func TestEnableWithoutBackupCodes(t *testing.T) {
	options := totpOptions()
	options.TOTP.DisableBackupCodes = true
	fixture := newFixture(t, options)
	user := fixture.createUser(t, "ada", "")
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusOK, browser.login("ada").Code)

	setup := browser.post(setupPath, map[string]any{})
	secret := decodeBody[setupResponse](t, setup).Secret
	recorder := browser.post(enablePath, map[string]any{"code": fixture.code(t, secret, 0), "password": testPassword})

	require.Equal(t, http.StatusOK, recorder.Code)
	require.JSONEq(t, `{"backupCodes":[]}`, recorder.Body.String())
	require.Empty(t, fixture.storedUser(t, user.ID).BackupCodeHashes)
}

func TestEnrollmentChangesNothingWhenTheLoginFails(t *testing.T) {
	testCases := []struct {
		name       string
		onLogin    auth.Hook
		failing    []string // session backend operations that fail during enable
		wantStatus int
	}{
		{
			name: "refused by OnLogin",
			onLogin: func(context.Context, *auth.Identity) (*auth.Identity, error) {
				return nil, &auth.Error{Kind: auth.ErrForbidden, Reason: "inactive user"}
			},
			wantStatus: http.StatusForbidden,
		},
		{name: "session start fails", failing: []string{"Revoke"}, wantStatus: http.StatusInternalServerError},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := totpOptions()
			options.TOTP.Required = true
			options.OnLogin = testCase.onLogin
			fixture := newFixture(t, options)
			user := fixture.createUser(t, "ada", "")
			browser := fixture.newClient(t)
			require.Equal(t, http.StatusAccepted, browser.login("ada").Code)
			secret := decodeBody[setupResponse](t, browser.post(setupPath, map[string]any{})).Secret
			if testCase.failing != nil {
				fixture.failSessions(t, testCase.failing...)
			}

			recorder := browser.post(enablePath, map[string]any{"code": fixture.code(t, secret, 0), "password": testPassword})

			require.Equal(t, testCase.wantStatus, recorder.Code, recorder.Body.String())
			stored := fixture.storedUser(t, user.ID)
			require.False(t, stored.TOTPEnabled)
			require.Empty(t, stored.BackupCodeHashes)
		})
	}
}

func TestEnableOnAFullSessionWritesNoSession(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user := fixture.createUser(t, "ada", "")
	browser := loggedInClient(t, fixture)
	secret := decodeBody[setupResponse](t, browser.post(setupPath, map[string]any{})).Secret
	fixture.failSessions(t, "Put")

	recorder := browser.post(enablePath, map[string]any{"code": fixture.code(t, secret, 0), "password": testPassword})

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	require.Len(t, decodeBody[enableResponse](t, recorder).BackupCodes, 10)
	require.True(t, fixture.storedUser(t, user.ID).TOTPEnabled)
}

// pausingStorage runs pause, once, after the next GetUserByID read the user and before it returns it: the reading
// request goes on with a snapshot that pause can make stale.
type pausingStorage struct {
	*MemoryStorage
	pause func()
}

func (s *pausingStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user, err := s.MemoryStorage.GetUserByID(ctx, id)
	if pause := s.pause; pause != nil {
		s.pause = nil
		pause()
	}
	return user, err
}

func TestConcurrentEnrollmentsEnableOnce(t *testing.T) {
	testCases := []struct {
		name     string
		required bool
	}{
		{name: "logins pending enrollment", required: true},
		{name: "full sessions"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := totpOptions()
			options.TOTP.Required = testCase.required
			fixture := newFixture(t, options)
			user := fixture.createUser(t, "ada", "")
			winner, loser := fixture.newClient(t), fixture.newClient(t)
			winner.login("ada")
			loser.login("ada")
			winnerSecret := decodeBody[setupResponse](t, winner.post(setupPath, map[string]any{})).Secret
			loserSecret := decodeBody[setupResponse](t, loser.post(setupPath, map[string]any{})).Secret
			storage := &pausingStorage{MemoryStorage: fixture.storage}
			fixture.provider.options.Storage = storage
			var winnerCodes []string
			storage.pause = func() { // the loser has read the user without TOTP; the winner enables meanwhile
				enable := winner.post(enablePath, map[string]any{"code": fixture.code(t, winnerSecret, 0), "password": testPassword})
				require.Equal(t, http.StatusOK, enable.Code, enable.Body.String())
				winnerCodes = decodeBody[enableResponse](t, enable).BackupCodes
			}

			recorder := loser.post(enablePath, map[string]any{"code": fixture.code(t, loserSecret, 30*time.Second), "password": testPassword})

			requireRefusal(t, recorder, http.StatusConflict, "totp_already_enabled")
			stored := fixture.storedUser(t, user.ID)
			require.Equal(t, winnerSecret, *stored.TOTPSecret)
			require.Len(t, stored.BackupCodeHashes, len(winnerCodes))
			_, found := matchingBackupCode(stored.BackupCodeHashes, winnerCodes[0])
			require.True(t, found, "the winner's backup codes stay")
			if testCase.required {
				_, err := fixture.sessionIdentity(t, loser)
				require.ErrorIs(t, err, auth.ErrUnauthenticated, "the losing enrollment gets no session")
			}
		})
	}
}

func TestBackupCodesAreDistinct(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	fixture.provider.backupCodeAlphabet = []rune("ab")
	fixture.provider.options.TOTP.BackupCodeLength = 1
	fixture.provider.options.TOTP.BackupCodeCount = 2

	// Two codes over two characters collide half of the time, unless duplicates are drawn again.
	for range 20 {
		codes, hashes, err := fixture.provider.newBackupCodes()
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"a", "b"}, codes)
		require.Len(t, hashes, 2)
	}
}

func TestBackupCodesUseTheConfiguredAlphabet(t *testing.T) {
	options := totpOptions()
	options.TOTP.BackupCodeAlphabet = "ABCDEFGH"
	options.TOTP.BackupCodeLength = 16
	options.TOTP.BackupCodeCount = 3
	fixture := newFixture(t, options)
	fixture.createUser(t, "ada", "")
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusOK, browser.login("ada").Code)

	_, backupCodes := enroll(t, fixture, browser)

	require.Len(t, backupCodes, 3)
	for _, code := range backupCodes {
		require.Len(t, code, 16)
		require.Empty(t, strings.Trim(code, "abcdefgh"), code)
	}
	recorder := fixture.pendingClient(t, "ada").post(verifyPath, map[string]any{"code": strings.ToUpper(backupCodes[0]), "backupCode": true})
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestTOTPRoutesRefuseForeignSessions(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user := fixture.createUser(t, "ada", "")
	impersonated := identityOf(user)
	impersonated.Impersonator = &auth.Identity{Provider: "password", Subject: uuid.NewString(), Active: true}

	testCases := []struct {
		name       string
		identity   *auth.Identity // nil: no session
		wantStatus int
		wantCode   string
	}{
		{name: "impersonating", identity: impersonated, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "another provider", identity: &auth.Identity{Provider: "github", Subject: "42", UserID: user.ID, Active: true}, wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated"},
		{name: "deleted user", identity: identityOf(&User{ID: uuid.New()}), wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated"},
		{name: "no session", wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			browser := fixture.newClient(t)
			if testCase.identity != nil {
				browser = fixture.clientWith(t, testCase.identity)
			}
			requireRefusal(t, browser.get(statusPath), testCase.wantStatus, testCase.wantCode)
			requireRefusal(t, browser.post(setupPath, map[string]any{}), testCase.wantStatus, testCase.wantCode)
			requireRefusal(t, browser.post(enablePath, map[string]any{"code": "000000", "password": testPassword}), testCase.wantStatus, testCase.wantCode)
			requireRefusal(t, browser.post(disablePath, map[string]any{"password": testPassword}), testCase.wantStatus, testCase.wantCode)
		})
	}
	require.False(t, fixture.storedUser(t, user.ID).TOTPEnabled)
}

func TestTOTPRoutesRefuseMalformedBodies(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	fixture.createUser(t, "ada", "")
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusOK, browser.login("ada").Code)

	for _, path := range []string{verifyPath, setupPath, enablePath, disablePath} {
		requireRefusal(t, browser.post(path, `{"unknown":true}`), http.StatusBadRequest, "invalid_request")
	}
}

func TestTOTPManagementStorageFailures(t *testing.T) {
	testCases := []struct {
		operation string
		path      string
		enrolled  bool
		body      func(code string) map[string]any
	}{
		{operation: "GetUserByID", path: setupPath, body: func(string) map[string]any { return map[string]any{} }},
		{operation: "ConsumeTOTPStep", path: enablePath, body: func(code string) map[string]any { return map[string]any{"code": code, "password": testPassword} }},
		{operation: "SetTOTP", path: enablePath, body: func(code string) map[string]any { return map[string]any{"code": code, "password": testPassword} }},
		{operation: "ClearTOTP", path: disablePath, enrolled: true, body: func(string) map[string]any { return map[string]any{"password": testPassword} }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.operation, func(t *testing.T) {
			fixture := newFixture(t, totpOptions())
			fixture.createUser(t, "ada", "")
			browser := fixture.newClient(t)
			require.Equal(t, http.StatusOK, browser.login("ada").Code)
			setup := browser.post(setupPath, map[string]any{})
			secret := decodeBody[setupResponse](t, setup).Secret
			if testCase.enrolled {
				require.Equal(t, http.StatusOK, browser.post(enablePath, map[string]any{"code": fixture.code(t, secret, 0), "password": testPassword}).Code)
			}
			fixture.failStorage(testCase.operation)

			recorder := browser.post(testCase.path, testCase.body(fixture.code(t, secret, 0)))

			requireRefusal(t, recorder, http.StatusInternalServerError, "internal")
			outcomes := fixture.outcomes.take()
			require.ErrorIs(t, outcomes[len(outcomes)-1].Err, errStorageDown)
		})
	}
}

func TestSessionBackendFailures(t *testing.T) {
	testCases := []struct {
		name     string
		options  Options
		prepare  func(t *testing.T, fixture *fixture) *client
		path     string
		body     any
		wantStep string // the step the error names
	}{
		{name: "login", prepare: func(t *testing.T, fixture *fixture) *client { return fixture.newClient(t) }, path: "/auth/password/login", body: map[string]any{"identifier": "ada", "password": testPassword}, wantStep: "save session identity of user"},
		{name: "login with a TOTP challenge", options: totpOptions(), prepare: func(t *testing.T, fixture *fixture) *client {
			requireSetTOTP(t, fixture.storage, mustUserID(t, fixture, "ada"), testSecret, nil)
			return fixture.newClient(t)
		}, path: "/auth/password/login", body: map[string]any{"identifier": "ada", "password": testPassword}, wantStep: "store pending login of user"},
		{name: "logout", prepare: loggedInClient, path: "/auth/password/logout", body: map[string]any{}, wantStep: "end session"},
		{name: "TOTP verify", options: totpOptions(), prepare: func(t *testing.T, fixture *fixture) *client {
			requireSetTOTP(t, fixture.storage, mustUserID(t, fixture, "ada"), testSecret, nil)
			return fixture.pendingClient(t, "ada")
		}, path: verifyPath, body: map[string]any{"code": "000000"}, wantStep: "read pending login"},
		{name: "TOTP setup", options: totpOptions(), prepare: loggedInClient, path: setupPath, body: map[string]any{}, wantStep: "read session identity"},
		{name: "TOTP enable", options: totpOptions(), prepare: loggedInClient, path: enablePath, body: map[string]any{"code": "000000", "password": testPassword}, wantStep: "read session identity"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFixture(t, testCase.options)
			fixture.createUser(t, "ada", "")
			browser := testCase.prepare(t, fixture)
			fixture.outcomes.take()
			fixture.failSessions(t)

			recorder := browser.post(testCase.path, testCase.body)

			requireRefusal(t, recorder, http.StatusInternalServerError, "internal")
			outcome := fixture.outcomes.last(t)
			require.Equal(t, auth.ResultError, outcome.Result)
			require.ErrorIs(t, outcome.Err, errStorageDown)
			require.ErrorContains(t, outcome.Err, testCase.wantStep)
		})
	}
}

func TestEndingAPendingLoginReportsAFailedRevocation(t *testing.T) {
	options := totpOptions()
	options.TOTP.MaximumAttempts = 1
	fixture := newFixture(t, options)
	fixture.createTOTPUser(t, "ada")
	browser := fixture.pendingClient(t, "ada")
	fixture.failSessions(t, "Revoke")

	recorder := browser.post(verifyPath, map[string]any{"code": "000000"})

	requireRefusal(t, recorder, http.StatusInternalServerError, "internal")
	outcome := fixture.outcomes.last(t)
	require.Equal(t, auth.ResultError, outcome.Result)
	require.ErrorIs(t, outcome.Err, errStorageDown)
	require.ErrorContains(t, outcome.Err, "end pending login")
}

func loggedInClient(t *testing.T, fixture *fixture) *client {
	t.Helper()
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusOK, browser.login("ada").Code)
	return browser
}

func mustUserID(t *testing.T, fixture *fixture, username string) uuid.UUID {
	t.Helper()
	user, err := fixture.storage.GetUserByUsername(t.Context(), username)
	require.NoError(t, err)
	return user.ID
}
