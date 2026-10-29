// Package dependency turns the errors of third-party packages into errors of this module. Its
// functions are safe for concurrent use.
package dependency

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
)

// Error returns "<operation>: <err>" with err's message but without its chain, so callers cannot start
// matching on a dependency's errors (LIB-010). A cancelled or expired context stays detectable: when err
// matches context.Canceled or context.DeadlineExceeded, that standard library sentinel is wrapped and its
// text appended. An HTTP call's *url.Error in err is reduced to `<operation>: <method> "<scheme>://<host>":
// <TransportFailure>`: its URL's path and query may carry personal data and its transport text may repeat
// bytes the server sent [LOG-009].
func Error(operation string, err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return fmt.Errorf("%s: %s %q: %w", operation, urlError.Op, origin(urlError.URL), TransportFailure(urlError.Err))
	}
	message := operation + ": " + err.Error()
	for _, contextError := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, contextError) {
			return fmt.Errorf("%s: %w", message, contextError)
		}
	}
	return errors.New(message)
}

// TransportFailure reduces the error of an HTTP transport to what is safe to record: the text of a
// malformed answer repeats the server's bytes (a header line, a status line), which may be personal data
// [LOG-009]. context.Canceled and context.DeadlineExceeded (also an http.Client timeout) are returned as
// they are, a dial error keeps its text (address and system error), another timeout is "timeout";
// anything else is named by the type of its innermost error. The result carries no dependency's type.
func TransportFailure(err error) error {
	var dialError *net.OpError
	var networkError net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.As(err, &dialError) && dialError.Op == "dial":
		return errors.New(dialError.Error())
	case errors.As(err, &networkError) && networkError.Timeout():
		return errors.New("timeout")
	}
	for errors.Unwrap(err) != nil {
		err = errors.Unwrap(err)
	}
	return fmt.Errorf("transport failure (%T)", err)
}

// origin is the scheme and host of raw, "" when it does not parse.
func origin(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
