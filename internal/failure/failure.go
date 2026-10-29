// Package failure classifies a failed action for the Outcome a provider reports, and answers and reports
// a provider's requests. Its functions and the Reporter are safe for concurrent use.
package failure

import (
	"context"
	"net/http"
	"net/url"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/redirect"
)

// Result is the Result of an action that failed with err (not nil): auth.ResultError when
// auth.ResponseFor answers err with 500, auth.ResultDenied (a refusal) otherwise.
func Result(err error) auth.Result {
	if status, _ := auth.ResponseFor(err); status == http.StatusInternalServerError {
		return auth.ResultError
	}
	return auth.ResultDenied
}

// Reporter answers a provider's failed requests and reports the outcome of every request.
type Reporter struct {
	Provider string        // set as Outcome.Provider
	Observer auth.Observer // optional; nil reports nothing
	ErrorURL string        // optional; where RefuseCallback sends the browser
}

// Refuse answers outcome.Err as JSON and reports the outcome as a failure.
func (r Reporter) Refuse(ctx context.Context, writer http.ResponseWriter, outcome auth.Outcome) {
	auth.WriteError(writer, outcome.Err)
	r.ReportFailure(ctx, outcome)
}

// RefuseCallback is Refuse, except that with ErrorURL set the failure (a refusal or code=internal)
// redirects to ErrorURL?code=<code>.
func (r Reporter) RefuseCallback(ctx context.Context, writer http.ResponseWriter, outcome auth.Outcome) {
	if r.ErrorURL == "" {
		r.Refuse(ctx, writer, outcome)
		return
	}
	_, response := auth.ResponseFor(outcome.Err)
	redirect.To(writer, redirect.WithQuery(r.ErrorURL, url.Values{"code": {response.Code}}))
	r.ReportFailure(ctx, outcome)
}

// ReportFailure reports outcome as denied (a refusal) or error (answered with 500).
func (r Reporter) ReportFailure(ctx context.Context, outcome auth.Outcome) {
	outcome.Result = Result(outcome.Err)
	r.Report(ctx, outcome)
}

// Report sets Provider on outcome and passes it to the Observer.
func (r Reporter) Report(ctx context.Context, outcome auth.Outcome) {
	if r.Observer == nil {
		return
	}
	outcome.Provider = r.Provider
	r.Observer(ctx, outcome)
}
