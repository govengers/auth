package auth

import (
	"errors"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"github.com/govengers/auth/internal/httpjson"
)

// ErrorResponse is the one JSON error shape of every library response.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"` // fixed per kind, safe to show; never err.Error()
}

type kindResponse struct {
	kind    error
	status  int
	code    string
	message string
}

var kindResponses = []kindResponse{
	{kind: ErrUnauthenticated, status: http.StatusUnauthorized, code: "unauthenticated", message: "authentication required"},
	{kind: ErrForbidden, status: http.StatusForbidden, code: "forbidden", message: "access denied"},
	{kind: ErrInvalidRequest, status: http.StatusBadRequest, code: "invalid_request", message: "invalid request"},
	{kind: ErrConflict, status: http.StatusConflict, code: "conflict", message: "conflict"},
}

var internalResponse = kindResponse{status: http.StatusInternalServerError, code: "internal", message: "internal error"}

// ResponseFor maps an error to its status and body. The Kind of the outermost *Error decides status and
// message, its Code replaces the default code; a bare sentinel maps by errors.Is; anything else is a
// 500 with code "internal". Reason and causes never reach the body.
func ResponseFor(err error) (int, ErrorResponse) {
	response := responseFor(err)
	return response.status, ErrorResponse{Code: response.code, Message: response.message}
}

func responseFor(err error) kindResponse {
	var refusal *Error
	if !errors.As(err, &refusal) {
		return responseForKind(err)
	}
	response := responseForKind(refusal.Kind)
	if refusal.Code != "" && response.kind != nil {
		response.code = refusal.Code
	}
	return response
}

func responseForKind(kind error) kindResponse {
	index := slices.IndexFunc(kindResponses, func(response kindResponse) bool {
		return errors.Is(kind, response.kind)
	})
	if index < 0 {
		return internalResponse
	}
	return kindResponses[index]
}

// WriteError writes ResponseFor(err) as JSON with Cache-Control: no-store.
func WriteError(writer http.ResponseWriter, err error) {
	status, response := ResponseFor(err)
	httpjson.Write(writer, status, response)
}

// IdentityResponse is the public view of an Identity: Claims, Attributes and Data are never exposed.
type IdentityResponse struct {
	Provider        string            `json:"provider"`
	Subject         string            `json:"subject"`
	UserID          string            `json:"userId,omitempty"` // empty for uuid.Nil
	Username        string            `json:"username,omitempty"`
	Name            string            `json:"name,omitempty"`
	Email           string            `json:"email,omitempty"`
	Picture         string            `json:"picture,omitempty"`
	Active          bool              `json:"active"`
	Roles           []string          `json:"roles"` // never null
	OIDCRoles       []string          `json:"oidcRoles,omitempty"`
	OIDCClientRoles []string          `json:"oidcClientRoles,omitempty"`
	Groups          []string          `json:"groups,omitempty"`
	Teams           []string          `json:"teams,omitempty"`
	Permissions     []Permission      `json:"permissions,omitempty"` // text form: ["builds:write"]
	Impersonator    *IdentityResponse `json:"impersonator,omitempty"`
}

// NewIdentityResponse returns the public view of identity, sharing no slice with it. A nil identity
// gives an empty view.
func NewIdentityResponse(identity *Identity) IdentityResponse {
	if identity == nil {
		return IdentityResponse{Roles: []string{}}
	}
	response := IdentityResponse{
		Provider:        identity.Provider,
		Subject:         identity.Subject,
		UserID:          userIDText(identity.UserID),
		Username:        identity.Username,
		Name:            identity.Name,
		Email:           identity.Email,
		Picture:         identity.Picture,
		Active:          identity.Active,
		Roles:           append([]string{}, identity.Roles...),
		OIDCRoles:       slices.Clone(identity.OIDCRoles),
		OIDCClientRoles: slices.Clone(identity.OIDCClientRoles),
		Groups:          slices.Clone(identity.Groups),
		Teams:           slices.Clone(identity.Teams),
		Permissions:     slices.Clone(identity.Permissions),
	}
	if identity.Impersonator != nil {
		response.Impersonator = new(NewIdentityResponse(identity.Impersonator))
	}
	return response
}

func userIDText(userID uuid.UUID) string {
	if userID == uuid.Nil {
		return ""
	}
	return userID.String()
}

// IdentityHandler answers 200 with the IdentityResponse of the identity in the request context and
// 401 without one. Mount it behind a Guard (recommended path "/auth/me"). It is safe for concurrent use.
func IdentityHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := IdentityFrom(request.Context())
		if identity == nil {
			WriteError(writer, ErrUnauthenticated)
			return
		}
		httpjson.Write(writer, http.StatusOK, NewIdentityResponse(identity))
	})
}
