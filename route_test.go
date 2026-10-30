package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegisterRoutes(t *testing.T) {
	answer := func(status int) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(status)
		})
	}
	serveMux := http.NewServeMux()

	RegisterRoutes(serveMux, []Route{
		{Method: http.MethodGet, Path: "/auth/oidc/login", Handler: answer(http.StatusFound)},
		{Method: http.MethodPost, Path: "/auth/password/login", Handler: answer(http.StatusNoContent)},
	})

	testCases := []struct {
		name       string
		method     string
		target     string
		wantStatus int
	}{
		{name: "get route", method: http.MethodGet, target: "/auth/oidc/login", wantStatus: http.StatusFound},
		{name: "post route", method: http.MethodPost, target: "/auth/password/login", wantStatus: http.StatusNoContent},
		{name: "wrong method", method: http.MethodPost, target: "/auth/oidc/login", wantStatus: http.StatusMethodNotAllowed},
		{name: "unknown path", method: http.MethodGet, target: "/auth/other", wantStatus: http.StatusNotFound},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			serveMux.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), testCase.method, testCase.target, nil))
			require.Equal(t, testCase.wantStatus, recorder.Code)
		})
	}
}
