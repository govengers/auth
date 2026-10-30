package auth

import (
	"errors"
	"strings"
)

// The four kinds of refusal. Callers branch on them with errors.Is; ResponseFor maps each to its status.
var (
	ErrUnauthenticated = errors.New("unauthenticated") // 401
	ErrForbidden       = errors.New("forbidden")       // 403
	ErrInvalidRequest  = errors.New("invalid request") // 400
	ErrConflict        = errors.New("conflict")        // 409
)

// Error is a refusal. Kind is one of the four sentinels; Code is the stable client-facing code
// (empty means the Kind's default code); Reason is server-side detail for the wide event and is
// never sent to a client (it may name a missing role); Err is an optional cause.
type Error struct {
	Kind   error
	Code   string
	Reason string
	Err    error
}

// ReasonInactive is the Reason of the ErrForbidden refusal of an inactive identity, shared by every
// authorization check and jwt.Signer.Sign.
const ReasonInactive = "inactive"

// Error returns "<kind>[: <code>][: <reason>][: <cause>]".
func (e *Error) Error() string {
	parts := make([]string, 0, 4)
	for _, part := range []string{errorText(e.Kind), e.Code, e.Reason, errorText(e.Err)} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, ": ")
}

// Unwrap returns the non-nil of Kind and Err, so errors.Is(err, ErrForbidden) matches.
func (e *Error) Unwrap() []error {
	causes := make([]error, 0, 2)
	for _, cause := range []error{e.Kind, e.Err} {
		if cause != nil {
			causes = append(causes, cause)
		}
	}
	return causes
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
