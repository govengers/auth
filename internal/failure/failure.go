// Package failure classifies a failed action for the Outcome a provider reports. Its functions are pure
// and safe for concurrent use.
package failure

import (
	"net/http"

	"github.com/govengers/auth"
)

// Result is the Result of an action that failed with err (not nil): auth.ResultError when
// auth.ResponseFor answers err with 500, auth.ResultDenied (a refusal) otherwise.
func Result(err error) auth.Result {
	if status, _ := auth.ResponseFor(err); status == http.StatusInternalServerError {
		return auth.ResultError
	}
	return auth.ResultDenied
}
