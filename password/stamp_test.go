package password

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

// requireRefreshEnds asserts that refreshing the client's session refuses it, which makes the Guard end it.
func (f *fixture) requireRefreshEnds(t *testing.T, browser *client, wantReason string) {
	t.Helper()
	refreshed, err := f.refresh(t, browser)
	require.ErrorIs(t, err, auth.ErrUnauthenticated)
	var refusal *auth.Error
	require.ErrorAs(t, err, &refusal)
	require.Equal(t, wantReason, refusal.Reason)
	require.Nil(t, refreshed)
}

func (f *fixture) requireRefreshKeeps(t *testing.T, browser *client) {
	t.Helper()
	refreshed, err := f.refresh(t, browser)
	require.NoError(t, err)
	require.NotNil(t, refreshed)
}

// verifiedClient returns a client with a full session of a TOTP user, logged in with the code of the next time
// step (every code is accepted once).
func (f *fixture) verifiedClient(t *testing.T, username string) *client {
	t.Helper()
	browser := f.pendingClient(t, username)
	f.clock.advance(30 * time.Second)
	recorder := browser.post(verifyPath, map[string]any{"code": f.code(t, testSecret, 0)})
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	return browser
}

func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	fixture := newFixture(t, Options{})
	user := fixture.createUser(t, "ada", "")
	guard, err := session.NewGuard(&session.GuardOptions{Store: fixture.sessions, Refreshers: []session.Refresher{fixture.provider}, RefreshInterval: time.Nanosecond})
	require.NoError(t, err)
	fixture.serveMux.Handle("GET /app", guard.RequireAPI()(auth.IdentityHandler()))
	stolen := loggedInClient(t, fixture)
	require.Equal(t, http.StatusOK, stolen.get("/app").Code)

	newHash, err := Hash("a completely new password", testParameters) // takes longer than the RefreshInterval
	require.NoError(t, err)
	require.NoError(t, fixture.storage.UpdatePasswordHash(t.Context(), user.ID, user.PasswordHash, newHash))

	require.Equal(t, http.StatusUnauthorized, stolen.get("/app").Code)
	require.False(t, stolen.hasSession(), "the Guard ended the session")
}

func TestTOTPEnrollmentEndsPreEnrollmentSessions(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user := fixture.createUser(t, "ada", "")
	attacker := loggedInClient(t, fixture)
	victim := loggedInClient(t, fixture)
	secret := decodeBody[setupResponse](t, victim.post(setupPath, map[string]any{})).Secret
	require.Equal(t, http.StatusOK, victim.post(enablePath, map[string]any{"code": fixture.code(t, secret, 0), "password": testPassword}).Code)

	requireRefusal(t, attacker.post(disablePath, map[string]any{"password": testPassword}), http.StatusUnauthorized, "unauthenticated")
	requireRefusal(t, attacker.get(statusPath), http.StatusUnauthorized, "unauthenticated")
	require.True(t, fixture.storedUser(t, user.ID).TOTPEnabled, "the pre-enrollment session cannot strip the second factor")
	fixture.requireRefreshEnds(t, attacker, "password or second factor changed")
	fixture.requireRefreshKeeps(t, victim)
}

func TestTOTPDisableKeepsOnlyTheActingSession(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	fixture.createTOTPUser(t, "ada")
	acting := fixture.verifiedClient(t, "ada")
	other := fixture.verifiedClient(t, "ada")

	require.Equal(t, http.StatusNoContent, acting.post(disablePath, map[string]any{"password": testPassword}).Code)

	fixture.requireRefreshKeeps(t, acting)
	fixture.requireRefreshEnds(t, other, "password or second factor changed")
}

func TestEnrollmentDuringLoginStampsTheNewSession(t *testing.T) {
	options := totpOptions()
	options.TOTP.Required = true
	fixture := newFixture(t, options)
	fixture.createUser(t, "ada", "")
	browser := fixture.newClient(t)
	require.Equal(t, http.StatusAccepted, browser.login("ada").Code)
	secret := decodeBody[setupResponse](t, browser.post(setupPath, map[string]any{})).Secret

	require.Equal(t, http.StatusOK, browser.post(enablePath, map[string]any{"code": fixture.code(t, secret, 0), "password": testPassword}).Code)

	fixture.requireRefreshKeeps(t, browser)
}

func TestLoginRehashKeepsItsSession(t *testing.T) {
	fixture := newFixture(t, Options{LegacyVerifier: VerifyBcrypt})
	user := fixture.createLegacyUser(t, bcryptHash(t, testPassword))
	browser := loggedInClient(t, fixture)
	require.NotEqual(t, user.PasswordHash, fixture.storedUser(t, user.ID).PasswordHash, "the login upgraded the hash")

	fixture.requireRefreshKeeps(t, browser)
}

func TestUnstampedSessionEnds(t *testing.T) {
	fixture := newFixture(t, totpOptions())
	user := fixture.createUser(t, "ada", "")
	browser := fixture.clientWith(t, identityOf(user)) // a session from before credential stamps

	fixture.requireRefreshEnds(t, browser, "session without credential stamp")
	requireRefusal(t, browser.post(disablePath, map[string]any{"password": testPassword}), http.StatusUnauthorized, "unauthenticated")
}

func TestCredentialStamp(t *testing.T) {
	user := &User{PasswordHash: "hash"}
	stamp := credentialStamp(user)
	require.Len(t, stamp, credentialStampLength)

	enrolled := *user
	enrolled.TOTPEnabled, enrolled.TOTPSecret = true, new(testSecret)
	require.NotEqual(t, stamp, credentialStamp(&enrolled))

	leftover := *user
	leftover.TOTPSecret = new(testSecret)
	require.Equal(t, stamp, credentialStamp(&leftover), "a secret left behind by ClearTOTP does not count")

	shifted := &User{PasswordHash: "hashtrue"}
	require.NotEqual(t, stamp, credentialStamp(shifted), "fields are length-prefixed")
}
