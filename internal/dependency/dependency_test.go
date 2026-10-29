package dependency

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestError(t *testing.T) {
	cause := errors.New("connection refused")

	err := Error("store session value", cause)

	require.EqualError(t, err, "store session value: connection refused")
	require.NotErrorIs(t, err, cause, "the dependency's error chain is dropped")
}
