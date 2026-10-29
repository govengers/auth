package auth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorError(t *testing.T) {
	cause := errors.New("storage down")
	testCases := []struct {
		name    string
		refusal *Error
		want    string
	}{
		{name: "kind only", refusal: &Error{Kind: ErrForbidden}, want: "forbidden"},
		{name: "kind and code", refusal: &Error{Kind: ErrUnauthenticated, Code: "invalid_credentials"}, want: "unauthenticated: invalid_credentials"},
		{name: "kind and reason", refusal: &Error{Kind: ErrForbidden, Reason: "missing role admin"}, want: "forbidden: missing role admin"},
		{name: "everything", refusal: &Error{Kind: ErrConflict, Code: "user_exists", Reason: "username taken", Err: cause}, want: "conflict: user_exists: username taken: storage down"},
		{name: "kind and cause", refusal: &Error{Kind: ErrInvalidRequest, Err: cause}, want: "invalid request: storage down"},
		{name: "no kind", refusal: &Error{Code: "x"}, want: "x"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.refusal.Error())
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("storage down")
	refusal := &Error{Kind: ErrForbidden, Err: cause}
	wrapped := fmt.Errorf("callback: %w", refusal)

	require.ErrorIs(t, wrapped, ErrForbidden)
	require.ErrorIs(t, wrapped, cause)
	require.NotErrorIs(t, wrapped, ErrUnauthenticated)

	var target *Error
	require.ErrorAs(t, wrapped, &target)
	require.Same(t, refusal, target)

	require.Equal(t, []error{ErrForbidden, cause}, refusal.Unwrap())
	require.Equal(t, []error{ErrConflict}, (&Error{Kind: ErrConflict}).Unwrap())
	require.Empty(t, (&Error{}).Unwrap())
}
