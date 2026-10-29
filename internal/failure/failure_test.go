package failure

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

func TestResult(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want auth.Result
	}{
		{name: "refusal", err: &auth.Error{Kind: auth.ErrUnauthenticated, Code: "invalid_token"}, want: auth.ResultDenied},
		{name: "wrapped refusal", err: fmt.Errorf("github: %w", &auth.Error{Kind: auth.ErrForbidden}), want: auth.ResultDenied},
		{name: "bare sentinel", err: auth.ErrInvalidRequest, want: auth.ResultDenied},
		{name: "conflict", err: auth.ErrConflict, want: auth.ResultDenied},
		{name: "plain error", err: errors.New("redis down"), want: auth.ResultError},
		{name: "refusal without kind", err: &auth.Error{Code: "odd"}, want: auth.ResultError},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, Result(testCase.err))
		})
	}
}
