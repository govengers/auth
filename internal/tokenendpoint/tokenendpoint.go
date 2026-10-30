// Package tokenendpoint turns the errors of an OAuth token request (golang.org/x/oauth2) into errors of
// this module that carry none of the endpoint's free text. It sits apart from internal/dependency so
// that packages without OAuth do not import oauth2. Its functions are safe for concurrent use.
package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/oauth2"

	"github.com/govengers/auth/internal/dependency"
)

// maximumErrorCodeLength bounds an OAuth error code worth recording; every code RFC 6749 and GitHub
// define is far shorter.
const maximumErrorCodeLength = 64

// Error returns "<operation>: token endpoint answered HTTP <status> [<OAuth error code>]" for an error
// answer of the endpoint (*oauth2.RetrieveError): its description, URI and body are the endpoint's free
// text and stay out of errors and outcomes (LOG-009). A failed call (*url.Error) or a cancelled or
// expired context goes through dependency.Error, so the context error stays detectable. Anything else
// is an answer oauth2 could not read (a malformed token response, whose parse error quotes its values):
// "<operation>: token endpoint answered an unreadable token response".
func Error(operation string, err error) error {
	var answer *oauth2.RetrieveError
	if !errors.As(err, &answer) {
		return nonAnswerError(operation, err)
	}
	message := operation + ": token endpoint answered"
	if answer.Response != nil {
		message += " HTTP " + strconv.Itoa(answer.Response.StatusCode)
	}
	if isErrorCode(answer.ErrorCode) {
		message += " " + answer.ErrorCode
	}
	return errors.New(message)
}

// nonAnswerError reduces an err that is no error answer of the endpoint (see Error).
func nonAnswerError(operation string, err error) error {
	var callError *url.Error
	if errors.As(err, &callError) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return dependency.Error(operation, err)
	}
	return errors.New(operation + ": token endpoint answered an unreadable token response")
}

// Refused reports whether err is an error answer of the endpoint below 500: the endpoint refused the
// request (an invalid code, verifier or client), as opposed to failing or not being reached.
func Refused(err error) bool {
	var answer *oauth2.RetrieveError
	return errors.As(err, &answer) && answer.Response != nil && answer.Response.StatusCode < http.StatusInternalServerError
}

// isErrorCode reports whether code looks like an OAuth error code (a-z and "_", at most 64 bytes).
func isErrorCode(code string) bool {
	return code != "" && len(code) <= maximumErrorCodeLength &&
		!strings.ContainsFunc(code, func(character rune) bool { return (character < 'a' || character > 'z') && character != '_' })
}
