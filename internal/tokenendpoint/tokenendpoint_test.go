package tokenendpoint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const marker = "marker-secret alice@example.test"

func answer(status int, code string) *oauth2.RetrieveError {
	return &oauth2.RetrieveError{
		Response: &http.Response{StatusCode: status}, Body: []byte("<p>" + marker + "</p>"),
		ErrorCode: code, ErrorDescription: marker, ErrorURI: "https://docs.example.com/" + marker,
	}
}

func TestErrorKeepsTheEndpointsTextOut(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want string
	}{
		{name: "error code", err: answer(http.StatusBadRequest, "invalid_grant"), want: "exchange code: token endpoint answered HTTP 400 invalid_grant"},
		{name: "wrapped", err: fmt.Errorf("oauth2: %w", answer(http.StatusOK, "bad_verification_code")), want: "exchange code: token endpoint answered HTTP 200 bad_verification_code"},
		{name: "malformed error code", err: answer(http.StatusBadRequest, marker), want: "exchange code: token endpoint answered HTTP 400"},
		{name: "overlong error code", err: answer(http.StatusBadRequest, strings.Repeat("a", 65)), want: "exchange code: token endpoint answered HTTP 400"},
		{name: "no error code", err: answer(http.StatusBadGateway, ""), want: "exchange code: token endpoint answered HTTP 502"},
		{name: "no response", err: &oauth2.RetrieveError{ErrorCode: "invalid_client", ErrorDescription: marker}, want: "exchange code: token endpoint answered invalid_client"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := Error("exchange code", testCase.err)

			require.EqualError(t, err, testCase.want)
			var retrieveError *oauth2.RetrieveError
			require.False(t, errors.As(err, &retrieveError), "the oauth2 error is dropped")
		})
	}
}

func TestErrorKeepsContextErrors(t *testing.T) {
	err := Error("exchange code", fmt.Errorf("Post \"https://idp.example.com/token\": %w", context.DeadlineExceeded))

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, "exchange code: Post")
}

func TestRefused(t *testing.T) {
	require.True(t, Refused(answer(http.StatusOK, "bad_verification_code")), "GitHub answers 200 with an error")
	require.True(t, Refused(fmt.Errorf("oauth2: %w", answer(http.StatusUnauthorized, "invalid_client"))))
	require.True(t, Refused(answer(http.StatusTooManyRequests, "")))
	require.False(t, Refused(answer(http.StatusInternalServerError, "")))
	require.False(t, Refused(answer(http.StatusBadGateway, "")))
	require.False(t, Refused(&oauth2.RetrieveError{ErrorCode: "invalid_grant"}), "no response, no status to judge")
	require.False(t, Refused(context.Canceled))
	require.False(t, Refused(nil))
}
