package dependency

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// thirdPartyError stands for a dependency's own error type.
type thirdPartyError struct{ cause error }

func (e *thirdPartyError) Error() string { return "client: " + e.cause.Error() }

func (e *thirdPartyError) Unwrap() error { return e.cause }

func TestError(t *testing.T) {
	cause := &thirdPartyError{cause: errors.New("connection refused")}

	err := Error("store session value", cause)

	require.EqualError(t, err, "store session value: client: connection refused")
	require.NotErrorIs(t, err, cause, "the dependency's error chain is dropped")
	var dependencyFailure *thirdPartyError
	require.False(t, errors.As(err, &dependencyFailure))
	require.NotErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestErrorKeepsContextErrors(t *testing.T) {
	for _, contextError := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(contextError.Error(), func(t *testing.T) {
			cause := &thirdPartyError{cause: contextError}

			err := Error("request admin token", cause)

			require.ErrorIs(t, err, contextError)
			require.EqualError(t, err, "request admin token: client: "+contextError.Error()+": "+contextError.Error())
			var dependencyFailure *thirdPartyError
			require.False(t, errors.As(err, &dependencyFailure), "only the standard library sentinel is wrapped")
		})
	}
}
