package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestResponseFor(t *testing.T) {
	cause := errors.New("cause with secret detail")
	testCases := []struct {
		name       string
		err        error
		wantStatus int
		want       ErrorResponse
	}{
		{name: "unauthenticated sentinel", err: ErrUnauthenticated, wantStatus: http.StatusUnauthorized, want: ErrorResponse{Code: "unauthenticated", Message: "authentication required"}},
		{name: "forbidden sentinel", err: ErrForbidden, wantStatus: http.StatusForbidden, want: ErrorResponse{Code: "forbidden", Message: "access denied"}},
		{name: "invalid request sentinel", err: ErrInvalidRequest, wantStatus: http.StatusBadRequest, want: ErrorResponse{Code: "invalid_request", Message: "invalid request"}},
		{name: "conflict sentinel", err: ErrConflict, wantStatus: http.StatusConflict, want: ErrorResponse{Code: "conflict", Message: "conflict"}},
		{name: "wrapped sentinel", err: fmt.Errorf("check: %w", ErrForbidden), wantStatus: http.StatusForbidden, want: ErrorResponse{Code: "forbidden", Message: "access denied"}},
		{name: "refusal with default code", err: &Error{Kind: ErrForbidden, Reason: "missing role admin"}, wantStatus: http.StatusForbidden, want: ErrorResponse{Code: "forbidden", Message: "access denied"}},
		{name: "refusal with custom code", err: &Error{Kind: ErrUnauthenticated, Code: "invalid_credentials", Err: cause}, wantStatus: http.StatusUnauthorized, want: ErrorResponse{Code: "invalid_credentials", Message: "authentication required"}},
		{name: "refusal wrapped twice", err: fmt.Errorf("a: %w", fmt.Errorf("b: %w", &Error{Kind: ErrConflict, Code: "user_exists"})), wantStatus: http.StatusConflict, want: ErrorResponse{Code: "user_exists", Message: "conflict"}},
		{name: "refusal kind decides over its cause", err: &Error{Kind: ErrForbidden, Err: ErrUnauthenticated}, wantStatus: http.StatusForbidden, want: ErrorResponse{Code: "forbidden", Message: "access denied"}},
		{name: "outermost refusal decides", err: &Error{Kind: ErrInvalidRequest, Code: "login_expired", Err: &Error{Kind: ErrUnauthenticated, Code: "login_denied"}}, wantStatus: http.StatusBadRequest, want: ErrorResponse{Code: "login_expired", Message: "invalid request"}},
		{name: "refusal with wrapped kind", err: &Error{Kind: fmt.Errorf("x: %w", ErrConflict)}, wantStatus: http.StatusConflict, want: ErrorResponse{Code: "conflict", Message: "conflict"}},
		{name: "refusal without kind", err: &Error{Code: "invalid_credentials", Reason: "r"}, wantStatus: http.StatusInternalServerError, want: ErrorResponse{Code: "internal", Message: "internal error"}},
		{name: "unknown error", err: cause, wantStatus: http.StatusInternalServerError, want: ErrorResponse{Code: "internal", Message: "internal error"}},
		{name: "nil", err: nil, wantStatus: http.StatusInternalServerError, want: ErrorResponse{Code: "internal", Message: "internal error"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			status, response := ResponseFor(testCase.err)
			require.Equal(t, testCase.wantStatus, status)
			require.Equal(t, testCase.want, response)
			require.NotContains(t, response.Message, "secret")
			require.NotContains(t, response.Message, "missing role")
		})
	}
}

func TestWriteError(t *testing.T) {
	recorder := httptest.NewRecorder()

	WriteError(recorder, &Error{Kind: ErrForbidden, Reason: "missing role admin", Err: errors.New("team org/secret")})

	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	require.JSONEq(t, `{"code":"forbidden","message":"access denied"}`, recorder.Body.String())
}

func TestNewIdentityResponse(t *testing.T) {
	identity := fullIdentity()

	response := NewIdentityResponse(identity)

	require.Equal(t, IdentityResponse{
		Provider:        "keycloak",
		Subject:         "subject-1",
		UserID:          "6f1c2a52-6c43-4c5e-9d3a-0f3d1c2b4a5e",
		Username:        "ada",
		Name:            "Ada Lovelace",
		Email:           "ada@example.com",
		Picture:         "https://example.com/ada.png",
		Active:          true,
		Roles:           []string{RoleAdmin},
		OIDCRoles:       []string{"realm-role"},
		OIDCClientRoles: []string{"client-role"},
		Groups:          []string{"/engineering"},
		Teams:           []string{"org/team"},
		Permissions:     []Permission{{Resource: "builds", Access: AccessWrite}, {Resource: AllResources, Access: AccessRead}},
		Impersonator:    &IdentityResponse{Provider: "password", Subject: "admin-1", Roles: []string{RoleAdmin}},
	}, response)

	response.Roles[0] = "changed"
	response.Groups[0] = "changed"
	response.Permissions[0] = Permission{Resource: "changed", Access: AccessRead}
	require.Equal(t, fullIdentity(), identity)
}

func TestNewIdentityResponseJSON(t *testing.T) {
	testCases := []struct {
		name     string
		identity *Identity
		want     string
	}{
		{
			name:     "full identity hides claims, attributes and data",
			identity: fullIdentity(),
			want: `{"provider":"keycloak","subject":"subject-1","userId":"6f1c2a52-6c43-4c5e-9d3a-0f3d1c2b4a5e","username":"ada",
				"name":"Ada Lovelace","email":"ada@example.com","picture":"https://example.com/ada.png","active":true,"roles":["admin"],
				"oidcRoles":["realm-role"],"oidcClientRoles":["client-role"],"groups":["/engineering"],"teams":["org/team"],
				"permissions":["builds:write","*:read"],"impersonator":{"provider":"password","subject":"admin-1","active":false,"roles":["admin"]}}`,
		},
		{
			name:     "nil user ID omitted and roles never null",
			identity: &Identity{Provider: "github", Subject: "42", UserID: uuid.Nil, Active: true},
			want:     `{"provider":"github","subject":"42","active":true,"roles":[]}`,
		},
		{
			name:     "nil identity",
			identity: nil,
			want:     `{"provider":"","subject":"","active":false,"roles":[]}`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			encoded, err := json.Marshal(NewIdentityResponse(testCase.identity))
			require.NoError(t, err)
			require.JSONEq(t, testCase.want, string(encoded))
		})
	}
}

func TestIdentityHandler(t *testing.T) {
	testCases := []struct {
		name       string
		identity   *Identity
		wantStatus int
		wantBody   string
	}{
		{name: "identity", identity: &Identity{Provider: "apikey", Subject: "ci", Active: true}, wantStatus: http.StatusOK, wantBody: `{"provider":"apikey","subject":"ci","active":true,"roles":[]}`},
		{name: "no identity", wantStatus: http.StatusUnauthorized, wantBody: `{"code":"unauthenticated","message":"authentication required"}`},
		{
			name:       "identity that does not encode",
			identity:   &Identity{Provider: "apikey", Subject: "ci", Active: true, Permissions: []Permission{{Resource: "Builds", Access: "write"}}},
			wantStatus: http.StatusInternalServerError, wantBody: `{"code":"internal","message":"internal error"}`,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/me", nil)
			if testCase.identity != nil {
				request = request.WithContext(WithIdentity(request.Context(), testCase.identity))
			}
			recorder := httptest.NewRecorder()

			IdentityHandler().ServeHTTP(recorder, request)

			require.Equal(t, testCase.wantStatus, recorder.Code)
			require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			require.JSONEq(t, testCase.wantBody, recorder.Body.String())
		})
	}
}
