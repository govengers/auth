package failure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestReporterRefusals(t *testing.T) {
	refusal := &auth.Error{Kind: auth.ErrUnauthenticated, Code: "login_failed"}
	testCases := []struct {
		name         string
		errorURL     string
		callback     bool
		err          error
		wantStatus   int
		wantLocation string
		wantResult   auth.Result
	}{
		{name: "refusal", err: refusal, wantStatus: http.StatusUnauthorized, wantResult: auth.ResultDenied},
		{name: "failure", err: errors.New("redis down"), wantStatus: http.StatusInternalServerError, wantResult: auth.ResultError},
		{name: "refusal with ErrorURL outside a callback", errorURL: "https://app.example.com/error", err: refusal, wantStatus: http.StatusUnauthorized, wantResult: auth.ResultDenied},
		{name: "callback without ErrorURL", callback: true, err: refusal, wantStatus: http.StatusUnauthorized, wantResult: auth.ResultDenied},
		{name: "callback refusal", errorURL: "https://app.example.com/error", callback: true, err: refusal, wantStatus: http.StatusFound, wantLocation: "https://app.example.com/error?code=login_failed", wantResult: auth.ResultDenied},
		{name: "callback failure", errorURL: "https://app.example.com/error", callback: true, err: errors.New("redis down"), wantStatus: http.StatusFound, wantLocation: "https://app.example.com/error?code=internal", wantResult: auth.ResultError},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var reported []auth.Outcome
			reporter := Reporter{Provider: "github", ErrorURL: testCase.errorURL, Observer: func(_ context.Context, outcome auth.Outcome) {
				reported = append(reported, outcome)
			}}
			recorder := httptest.NewRecorder()
			outcome := auth.Outcome{Provider: "other", Action: auth.ActionCallback, Err: testCase.err}

			if testCase.callback {
				reporter.RefuseCallback(t.Context(), recorder, outcome)
			} else {
				reporter.Refuse(t.Context(), recorder, outcome)
			}

			require.Equal(t, testCase.wantStatus, recorder.Code)
			require.Equal(t, testCase.wantLocation, recorder.Header().Get("Location"))
			require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			require.Equal(t, []auth.Outcome{{Provider: "github", Action: auth.ActionCallback, Result: testCase.wantResult, Err: testCase.err}}, reported)
		})
	}
}

func TestReporterWithoutObserverReportsNothing(t *testing.T) {
	recorder := httptest.NewRecorder()

	Reporter{Provider: "github"}.Refuse(t.Context(), recorder, auth.Outcome{Err: auth.ErrForbidden})
	Reporter{Provider: "github"}.Report(t.Context(), auth.Outcome{Result: auth.ResultSuccess})

	require.Equal(t, http.StatusForbidden, recorder.Code)
}
