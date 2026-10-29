package oidc_test

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/fakeprovider"
	"github.com/govengers/auth/oidc"
	"github.com/govengers/auth/session"
)

const loggedOutPage = "<!doctype html><html><head><title>Logged out</title></head><body></body></html>"

// logouts records the identities OnLogout received.
type logouts struct {
	mutex      sync.Mutex
	identities []*auth.Identity
}

func (l *logouts) hook(_ context.Context, identity *auth.Identity) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.identities = append(l.identities, identity)
}

func (l *logouts) subjects() []string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	subjects := []string{}
	for _, identity := range l.identities {
		subjects = append(subjects, identity.Subject)
	}
	return subjects
}

func TestLogoutSendsTheIDTokenHintToTheEndSessionEndpoint(t *testing.T) {
	issuer := startIssuer(t, nil)
	ended := &logouts{}
	application := newApplication(t, issuer, func(options *oidc.Options) { options.OnLogout = ended.hook })
	person := newBrowser(t)
	require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)
	identityToken := person.sessionValue(application.store, providerName+".id_token")

	response := person.get(application.handler, prefix+"/logout", nil)

	require.Equal(t, http.StatusFound, response.Code)
	location := response.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, issuer.IssuerURL()+"/end_session?"), location)
	query := queryOf(t, location)
	require.Equal(t, clientID, query.Get("client_id"))
	require.Equal(t, identityToken, query.Get("id_token_hint"))
	require.Equal(t, externalURL+"/", query.Get("post_logout_redirect_uri"))
	require.Equal(t, http.StatusUnauthorized, person.me(application))
	require.Equal(t, []string{"user-1"}, ended.subjects())
	require.Equal(t, auth.ActionLogout, application.outcomes.last(t).Action)
	require.Equal(t, auth.ResultSuccess, application.outcomes.last(t).Result)

	require.Equal(t, externalURL+"/", person.issuer(location))
	require.Equal(t, []string{identityToken}, issuer.IDTokenHints())
}

func TestLogoutWithoutHintGoesToThePostLogoutURL(t *testing.T) {
	testCases := []struct {
		name          string
		omitEndpoint  bool
		signedIn      bool
		postLogoutURL string
		wantLocation  string
		wantLogouts   []string
	}{
		{name: "IdP without end_session_endpoint", omitEndpoint: true, signedIn: true, postLogoutURL: "https://www.example.com/bye", wantLocation: "https://www.example.com/bye", wantLogouts: []string{"user-1"}},
		{name: "no session", omitEndpoint: false, signedIn: false, postLogoutURL: "https://www.example.com/bye", wantLocation: "https://www.example.com/bye", wantLogouts: []string{}},
		{name: "path made absolute", omitEndpoint: true, signedIn: true, postLogoutURL: "/bye?x=1", wantLocation: externalURL + "/bye?x=1", wantLogouts: []string{"user-1"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ended := &logouts{}
			issuer := startIssuer(t, func(options *fakeprovider.OIDCOptions) { options.OmitEndSessionEndpoint = testCase.omitEndpoint })
			application := newApplication(t, issuer, func(options *oidc.Options) {
				options.OnLogout = ended.hook
				options.PostLogoutURL = testCase.postLogoutURL
			})
			person := newBrowser(t)
			if testCase.signedIn {
				require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)
			}

			response := person.get(application.handler, prefix+"/logout", nil)

			require.Equal(t, http.StatusFound, response.Code)
			require.Equal(t, testCase.wantLocation, response.Header().Get("Location"))
			require.Equal(t, testCase.wantLogouts, ended.subjects())
			require.Equal(t, http.StatusUnauthorized, person.me(application))
			require.NoError(t, application.outcomes.last(t).Err, "no session is nothing to report")
		})
	}
}

func TestLogoutOfAnotherProvidersSessionSendsNoHint(t *testing.T) {
	application := newApplication(t, startIssuer(t, nil), nil)
	person := newBrowser(t)
	person.plantSession(application.store, &auth.Identity{Provider: "password", Subject: "user-9", Active: true})

	response := person.get(application.handler, prefix+"/logout", nil)

	require.Equal(t, externalURL+"/", response.Header().Get("Location"))
	require.Equal(t, http.StatusUnauthorized, person.me(application), "the session ends all the same")
}

func TestLogoutWhileImpersonatingUsesTheRealLogin(t *testing.T) {
	issuer := startIssuer(t, nil)
	application := newApplication(t, issuer, nil)
	person := newBrowser(t)
	require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)
	person.replaceIdentity(application.store, func(real *auth.Identity) *auth.Identity {
		return &auth.Identity{Provider: "password", Subject: "user-9", Active: true, Impersonator: real}
	})

	response := person.get(application.handler, prefix+"/logout", nil)

	require.True(t, strings.HasPrefix(response.Header().Get("Location"), issuer.IssuerURL()+"/end_session?"))
}

func TestFrontChannelLogout(t *testing.T) {
	testCases := []struct {
		name          string
		target        string
		header        http.Header
		disableIframe bool
		session       string // "own", "foreign" or "none"
		wantStatus    int
		wantEnded     bool
	}{
		{name: "matching iss and sid", target: "/frontchannel-logout?iss={issuer}&sid=idp-session-1", session: "own", wantStatus: http.StatusOK, wantEnded: true},
		{name: "no iss and sid", target: "/frontchannel-logout", session: "own", wantStatus: http.StatusOK, wantEnded: true},
		{name: "iss and sid on /logout", target: "/logout?iss={issuer}&sid=idp-session-1", session: "own", wantStatus: http.StatusOK, wantEnded: true},
		{name: "iframe on /logout", target: "/logout", header: http.Header{"Sec-Fetch-Dest": {"iframe"}}, session: "own", wantStatus: http.StatusOK, wantEnded: true},
		{name: "iframe detection disabled", target: "/logout", header: http.Header{"Sec-Fetch-Dest": {"iframe"}}, disableIframe: true, session: "own", wantStatus: http.StatusFound, wantEnded: true},
		{name: "iss without sid", target: "/frontchannel-logout?iss={issuer}", session: "own", wantStatus: http.StatusBadRequest},
		{name: "sid without iss", target: "/frontchannel-logout?sid=idp-session-1", session: "own", wantStatus: http.StatusBadRequest},
		{name: "empty iss and sid", target: "/frontchannel-logout?iss=&sid=", session: "own", wantStatus: http.StatusBadRequest},
		{name: "wrong issuer", target: "/frontchannel-logout?iss=https://evil.example&sid=idp-session-1", session: "own", wantStatus: http.StatusBadRequest},
		{name: "sid mismatch", target: "/frontchannel-logout?iss={issuer}&sid=other-session", session: "own", wantStatus: http.StatusBadRequest},
		{name: "another provider's session", target: "/frontchannel-logout?iss={issuer}&sid=idp-session-1", session: "foreign", wantStatus: http.StatusOK},
		{name: "no session", target: "/frontchannel-logout?iss={issuer}&sid=idp-session-1", session: "none", wantStatus: http.StatusOK},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			issuer := startIssuer(t, nil)
			ended := &logouts{}
			application := newApplication(t, issuer, func(options *oidc.Options) {
				options.DisableIframeLogoutDetection = testCase.disableIframe
				options.OnLogout = ended.hook
			})
			person := newBrowser(t)
			switch testCase.session {
			case "own":
				require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)
			case "foreign":
				person.plantSession(application.store, &auth.Identity{Provider: "other", Subject: "user-9", Active: true})
			}
			target := prefix + strings.ReplaceAll(testCase.target, "{issuer}", issuer.IssuerURL())

			response := person.get(application.handler, target, testCase.header)

			require.Equal(t, testCase.wantStatus, response.Code, response.Body.String())
			if testCase.wantStatus == http.StatusOK {
				require.Equal(t, loggedOutPage, response.Body.String())
				require.Equal(t, "no-store, must-revalidate", response.Header().Get("Cache-Control"))
				require.Equal(t, "no-cache", response.Header().Get("Pragma"))
				require.Equal(t, auth.ActionFrontChannelLogout, application.outcomes.last(t).Action)
			}
			if testCase.wantStatus == http.StatusBadRequest {
				require.Equal(t, auth.ResultDenied, application.outcomes.last(t).Result)
			}
			sessionAlive := person.me(application) == http.StatusOK
			require.Equal(t, testCase.session != "none" && !testCase.wantEnded, sessionAlive)
			if testCase.wantEnded {
				require.Equal(t, []string{"user-1"}, ended.subjects())
			}
		})
	}
}

func TestLogoutRefusesACrossSiteRequestButNotTheIdPsFrontChannelCall(t *testing.T) {
	crossSite := http.Header{"Sec-Fetch-Site": {"cross-site"}}
	testCases := []struct {
		name       string
		target     string
		header     http.Header
		wantStatus int
	}{
		{name: "RP-initiated", target: "/logout", header: crossSite, wantStatus: http.StatusForbidden},
		{name: "RP-initiated, iframe detection disabled", target: "/logout", header: http.Header{"Sec-Fetch-Site": {"cross-site"}, "Sec-Fetch-Dest": {"iframe"}}, wantStatus: http.StatusForbidden},
		{name: "front-channel route", target: "/frontchannel-logout?iss={issuer}&sid=idp-session-1", header: crossSite, wantStatus: http.StatusOK},
		{name: "front-channel on /logout", target: "/logout?iss={issuer}&sid=idp-session-1", header: crossSite, wantStatus: http.StatusOK},
		{name: "same-origin", target: "/logout", header: http.Header{"Sec-Fetch-Site": {"same-origin"}}, wantStatus: http.StatusFound},
		{name: "same-site", target: "/logout", header: http.Header{"Sec-Fetch-Site": {"same-site"}}, wantStatus: http.StatusFound},
		{name: "user-initiated", target: "/logout", header: http.Header{"Sec-Fetch-Site": {"none"}}, wantStatus: http.StatusFound},
		{name: "no header", target: "/logout", wantStatus: http.StatusFound},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			issuer := startIssuer(t, nil)
			ended := &logouts{}
			application := newApplication(t, issuer, func(options *oidc.Options) {
				options.OnLogout = ended.hook
				options.DisableIframeLogoutDetection = testCase.header.Get("Sec-Fetch-Dest") != ""
			})
			person := newBrowser(t)
			require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)
			target := prefix + strings.ReplaceAll(testCase.target, "{issuer}", issuer.IssuerURL())

			response := person.get(application.handler, target, testCase.header)

			require.Equal(t, testCase.wantStatus, response.Code, response.Body.String())
			if testCase.wantStatus != http.StatusForbidden {
				require.Equal(t, http.StatusUnauthorized, person.me(application))
				return
			}
			require.JSONEq(t, `{"code":"forbidden","message":"access denied"}`, response.Body.String())
			require.Empty(t, response.Result().Cookies())
			require.Equal(t, http.StatusOK, person.me(application), "the session is untouched")
			require.Empty(t, ended.subjects())
			outcome := application.outcomes.last(t)
			require.Equal(t, auth.ActionLogout, outcome.Action)
			require.Equal(t, auth.ResultDenied, outcome.Result)
			require.ErrorIs(t, outcome.Err, auth.ErrForbidden)
		})
	}
}

func TestLogoutAnswers500WhenTheSessionCannotBeEnded(t *testing.T) {
	testCases := []struct {
		name       string
		target     string
		wantType   string
		wantAction auth.Action
	}{
		{name: "RP-initiated", target: "/logout", wantType: "application/json", wantAction: auth.ActionLogout},
		{name: "front-channel", target: "/frontchannel-logout", wantType: "text/plain; charset=utf-8", wantAction: auth.ActionFrontChannelLogout},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &failingBackend{}
			store := newStoreOn(t, backend)
			application := newApplicationOn(t, store, startIssuer(t, nil), nil)
			person := newBrowser(t)
			require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)
			backend.failRevoke()

			response := person.get(application.handler, prefix+testCase.target, nil)

			require.Equal(t, http.StatusInternalServerError, response.Code)
			require.Equal(t, testCase.wantType, response.Header().Get("Content-Type"))
			require.Equal(t, auth.Outcome{Provider: providerName, Action: testCase.wantAction, Result: auth.ResultError}, withoutErrorAndIdentity(application.outcomes.last(t)))
		})
	}
}

func TestLogoutIgnoresAClientDisconnect(t *testing.T) {
	issuer := startIssuer(t, nil)
	testCases := []struct {
		name     string
		target   string
		wantHint bool
	}{
		{name: "RP-initiated", target: prefix + "/logout", wantHint: true},
		{name: "front-channel", target: prefix + "/frontchannel-logout?iss=" + url.QueryEscape(issuer.IssuerURL()) + "&sid=idp-session-1"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ended := &logouts{}
			application := newApplicationOn(t, newStoreOn(t, &failingBackend{}), issuer, func(options *oidc.Options) { options.OnLogout = ended.hook })
			person := newBrowser(t)
			require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)
			disconnected, disconnect := context.WithCancel(t.Context())
			disconnect()
			request := httptest.NewRequestWithContext(disconnected, http.MethodGet, testCase.target, nil)
			for _, cookie := range person.cookies {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()

			application.handler.ServeHTTP(response, request)

			require.Equal(t, []string{"user-1"}, ended.subjects(), "OnLogout still learns who logged out")
			require.Equal(t, testCase.wantHint, queryOf(t, response.Header().Get("Location")).Has("id_token_hint"))
			require.Equal(t, http.StatusUnauthorized, person.me(application), "the session ended")
		})
	}
}

func TestLogoutDegradesWhenTheSessionCannotBeRead(t *testing.T) {
	issuer := startIssuer(t, nil)
	frontChannel := prefix + "/frontchannel-logout?iss=" + url.QueryEscape(issuer.IssuerURL()) + "&sid=idp-session-1"
	testCases := []struct {
		name        string
		target      string
		failingKey  string
		wantStatus  int
		wantAction  auth.Action
		wantLogouts []string
	}{
		{name: "RP-initiated, identity", target: prefix + "/logout", failingKey: "identity", wantStatus: http.StatusFound, wantAction: auth.ActionLogout, wantLogouts: []string{}},
		{name: "RP-initiated, ID token", target: prefix + "/logout", failingKey: providerName + ".id_token", wantStatus: http.StatusFound, wantAction: auth.ActionLogout, wantLogouts: []string{"user-1"}},
		{name: "front-channel, identity", target: frontChannel, failingKey: "identity", wantStatus: http.StatusOK, wantAction: auth.ActionFrontChannelLogout, wantLogouts: []string{}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &failingBackend{}
			ended := &logouts{}
			application := newApplicationOn(t, newStoreOn(t, backend), issuer, func(options *oidc.Options) { options.OnLogout = ended.hook })
			person := newBrowser(t)
			require.Equal(t, http.StatusFound, person.signIn(application, prefix+"/login").Code)
			signedIn := maps.Clone(person.cookies)
			backend.failKey(testCase.failingKey)

			response := person.get(application.handler, testCase.target, nil)

			require.Equal(t, testCase.wantStatus, response.Code)
			require.False(t, queryOf(t, response.Header().Get("Location")).Has("id_token_hint"))
			require.Equal(t, testCase.wantLogouts, ended.subjects())
			outcome := application.outcomes.last(t)
			require.Equal(t, testCase.wantAction, outcome.Action)
			require.Equal(t, auth.ResultSuccess, outcome.Result)
			require.ErrorIs(t, outcome.Err, errBackendDown, "the lost hook or hint shows on the outcome")
			backend.failKey("")
			person.cookies = signedIn
			require.Equal(t, http.StatusUnauthorized, person.me(application), "the session ended all the same")
		})
	}
}

func withoutErrorAndIdentity(outcome auth.Outcome) auth.Outcome {
	outcome.Err, outcome.Identity = nil, nil
	return outcome
}

// failingBackend is a memory backend whose Revoke fails once failRevoke was called, whose Put and Get of
// the key set by failKey fail, and whose Get fails on a done context.
type failingBackend struct {
	session.Backend
	mutex      sync.Mutex
	failing    bool
	failingKey string
}

var errBackendDown = errors.New("backend down")

func (b *failingBackend) failRevoke() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.failing = true
}

func (b *failingBackend) failKey(key string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.failingKey = key
}

func (b *failingBackend) fails(key string) bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return key == b.failingKey
}

func (b *failingBackend) Revoke(ctx context.Context, sessionID string, ttl time.Duration) error {
	b.mutex.Lock()
	failing := b.failing
	b.mutex.Unlock()
	if failing {
		return errBackendDown
	}
	return b.Backend.Revoke(ctx, sessionID, ttl)
}

func (b *failingBackend) Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error {
	if b.fails(key) {
		return errBackendDown
	}
	return b.Backend.Put(ctx, sessionID, key, value, ttl)
}

// Get fails on a done context, as a network backend does.
func (b *failingBackend) Get(ctx context.Context, sessionID, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if b.fails(key) {
		return nil, false, errBackendDown
	}
	return b.Backend.Get(ctx, sessionID, key)
}

func newStoreOn(t *testing.T, backend *failingBackend) *session.Store {
	t.Helper()
	memory, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	backend.Backend = memory
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	return store
}

// plantSession gives the browser a session holding identity, as another provider's login would.
func (b *browser) plantSession(store *session.Store, identity *auth.Identity) {
	b.t.Helper()
	b.get(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current, err := store.Start(request.Context(), writer, request)
		require.NoError(b.t, err)
		require.NoError(b.t, current.SaveIdentity(request.Context(), identity))
	}), "/", nil)
}

// replaceIdentity stores change(identity) in the browser's session, keeping the session.
func (b *browser) replaceIdentity(store *session.Store, change func(identity *auth.Identity) *auth.Identity) {
	b.t.Helper()
	request := httptest.NewRequestWithContext(b.t.Context(), http.MethodGet, "/", nil)
	for _, cookie := range b.cookies {
		request.AddCookie(cookie)
	}
	current, err := store.Open(request)
	require.NoError(b.t, err)
	identity, err := current.Identity(b.t.Context())
	require.NoError(b.t, err)
	require.NoError(b.t, current.SaveIdentity(b.t.Context(), change(identity)))
}
