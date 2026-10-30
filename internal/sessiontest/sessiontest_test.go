package sessiontest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/session"
)

func TestImpersonateAndStop(t *testing.T) {
	backend, err := session.NewMemoryBackend(nil)
	require.NoError(t, err)
	store, err := session.NewStore(&session.StoreOptions{Backend: backend, EncryptionKey: []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	current, err := store.Start(t.Context(), recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	require.NoError(t, err)
	admin := &auth.Identity{Provider: "password", Subject: "admin-1", Active: true}
	require.NoError(t, current.SaveIdentity(t.Context(), admin))
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	request.AddCookie(recorder.Result().Cookies()[0])
	target := &auth.Identity{Provider: "password", Subject: "user-2", Active: true}

	impersonated := Impersonate(t, store, request, target)

	require.Equal(t, "user-2", impersonated.Subject)
	require.Equal(t, admin, impersonated.Impersonator)
	require.Equal(t, admin, StopImpersonating(t, store, request))
}
