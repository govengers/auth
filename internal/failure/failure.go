// Package failure classifies a failed action for the Outcome a provider reports, and answers and reports
// a provider's requests. Its functions and the Reporter are safe for concurrent use.
package failure

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/redirect"
)

// UnlessAbsent returns err unless it only says that there is nothing (auth.ErrUnauthenticated), e.g. no
// session or no identity in it.
func UnlessAbsent(err error) error {
	if errors.Is(err, auth.ErrUnauthenticated) {
		return nil
	}
	return err
}

// Result is the Result of an action that failed with err (not nil): auth.ResultError when
// auth.ResponseFor answers err with 500, auth.ResultDenied (a refusal) otherwise.
func Result(err error) auth.Result {
	if status, _ := auth.ResponseFor(err); status == http.StatusInternalServerError {
		return auth.ResultError
	}
	return auth.ResultDenied
}

// ReporterOptions configures NewReporter.
type ReporterOptions struct {
	Provider string        // required; set as Outcome.Provider
	Observer auth.Observer // optional; nil reports nothing
	ErrorURL string        // optional; where RefuseCallback sends the browser: a path or an absolute http(s) URL, without a fragment
}

// Reporter answers a provider's failed requests and reports the outcome of every request.
type Reporter struct {
	options ReporterOptions
}

// NewReporter validates options and returns a Reporter working on a copy of them.
func NewReporter(options *ReporterOptions) (*Reporter, error) {
	if options == nil || options.Provider == "" {
		return nil, errors.New("failure reporter: Provider is required")
	}
	if options.ErrorURL != "" && !redirect.IsTarget(options.ErrorURL) {
		return nil, errors.New("failure reporter: ErrorURL must be a path or an absolute http(s) URL, without a fragment")
	}
	return &Reporter{options: *options}, nil
}

// Refuse answers outcome.Err as JSON and reports the outcome as a failure.
func (r *Reporter) Refuse(ctx context.Context, writer http.ResponseWriter, outcome auth.Outcome) {
	auth.WriteError(writer, outcome.Err)
	r.ReportFailure(ctx, outcome)
}

// RefuseCallback is Refuse, except that with ErrorURL set the failure (a refusal or code=internal)
// redirects to ErrorURL?code=<code>.
func (r *Reporter) RefuseCallback(ctx context.Context, writer http.ResponseWriter, outcome auth.Outcome) {
	if r.options.ErrorURL == "" {
		r.Refuse(ctx, writer, outcome)
		return
	}
	_, response := auth.ResponseFor(outcome.Err)
	redirect.To(writer, redirect.WithQuery(r.options.ErrorURL, url.Values{"code": {response.Code}}))
	r.ReportFailure(ctx, outcome)
}

// ReportFailure reports outcome as denied (a refusal) or error (answered with 500).
func (r *Reporter) ReportFailure(ctx context.Context, outcome auth.Outcome) {
	outcome.Result = Result(outcome.Err)
	r.Report(ctx, outcome)
}

// Report sets Provider on outcome and passes it to the Observer.
func (r *Reporter) Report(ctx context.Context, outcome auth.Outcome) {
	if r.options.Observer == nil {
		return
	}
	outcome.Provider = r.options.Provider
	r.options.Observer(ctx, outcome)
}
